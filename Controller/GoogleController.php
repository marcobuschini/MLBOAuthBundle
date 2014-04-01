<?php

namespace MLB\OAuthBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;

use Acme\DemoBundle\Entity\User;

/**
  * Controller actions to interface with Google's OAuth for user registration, and login.
  */
class GoogleController extends Controller
{
	
    /**
     * Logs a user in using Google's OAuth
     */
    public function loginAction()
    {
        $auth = $this->container->getParameter('mlbo_auth');

        $auth = $auth['google'];
        $state = hash('sha512', rand(), false);
        $session = $this->getRequest()->getSession();
        $session->set('state', $state);

        $uri = "https://accounts.google.com/o/oauth2/auth?client_id=".$auth["client_id"].
               "&response_type=code&scope=".urlencode('https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email').'&'.
               "redirect_uri=".urlencode($auth["redirect_uri"])."&".
               "state=".$state;
        return $this->redirect($uri);
    }
	
    /**
     * Registers a user using Goole's OAuth.
     */
    public function connectAction(Request $request)
    {
        if($request->query->has('state') && $request->query->has('code'))
        {
            $auth = $this->container->getParameter('mlbo_auth');
            $auth = $auth['google'];
            if($request->query->get('state') == $request->getSession()->get("state"))
            {
                $code = $request->query->get('code');
                $client_id = $auth["client_id"];
                $client_secret = $auth["client_secret"];
                $redirect_uri = $auth["redirect_uri"];
                $grant_type="authorization_code";

                $encoded = 'code='.$code
                          .'&client_id='.$client_id
                          .'&client_secret='.$client_secret
                          .'&redirect_uri='.urlencode($redirect_uri)
                          .'&grant_type='.$grant_type;
                $ch = curl_init("https://accounts.google.com/o/oauth2/token");
                curl_setopt($ch, CURLOPT_POSTFIELDS,  $encoded);
                curl_setopt($ch, CURLOPT_HEADER, false);
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                $result = curl_exec($ch);
                curl_close($ch);
                $result = json_decode($result, true);

                if(array_key_exists('error', $result))
                {
                    return new Response('Invalid request', 401, array('content-type' => 'text/html'));
                }

                $google_access_token = $result["access_token"];
                $id_token = $result["id_token"];

                $ch = curl_init('https://www.googleapis.com/userinfo/v2/me');
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Host: www.googleapis.com', 'Authorization: Bearer '.$google_access_token, 'Content-length: 0'));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                $result = curl_exec($ch);
                curl_close($ch);
                $object = json_decode($result, true);

                $google_id = $object['id'];

                $userManager = $this->container->get('fos_user.user_manager');
                $user = $userManager->findUserBy(array('google_id' => $google_id));
                if($user == null)
                {
                    $user = new User();
                    $user->setPassword('');
                }

                $user->setUserName($object['name']);
                $user->setEmail($object['email']);
                $user->setGoogleId($google_id);
                $user->setGoogleAccessToken($google_access_token);
                $userManager->updateUser($user, true);

                // Here, "main" is the name of the firewall in your security.yml
                $token = new UsernamePasswordToken($user, $user->getPassword(), "main", $user->getRoles());
                $this->get("security.context")->setToken($token);

                // Fire the login event
                // Logging the user in as above doesn't do this automatically
                $event = new InteractiveLoginEvent($request, $token);
                $this->get("event_dispatcher")->dispatch("security.interactive_login", $event);
            }
        } else {		
            return new Response('Invalid request', 401, array('content-type' => 'text/html'));
        }
    }
}
