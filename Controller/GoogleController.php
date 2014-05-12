<?php

namespace MLB\OAuthBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;

/**
  * Controller actions to interface with Google's OAuth for user registration, and login.
  */
class GoogleController extends Controller
{
    /**
     * Holds private configuratio data.
     */
    private $config = null;
	
    /**
     * Logs a user in using Google's OAuth.
     */
    public function loginAction()
    {
        $google = $this->readConfig();

        // Creates an hash, and saves in the session. It will be used in
        // multiple authetication stems.
        $state = hash('sha512', rand(), false);
        $session = $this->getRequest()->getSession();
        $session->set('state', $state);

        // Redirect to the Google Login page.
        $uri = 'https://accounts.google.com/o/oauth2/auth?client_id='.$google['client_id'].
               '&response_type=code&scope='.urlencode($google['scope']).'&'.
               'redirect_uri='.urlencode($google['redirect_uri']).'&'.
               'state='.$state;
        return $this->redirect($uri);
    }
	
    /**
     * Registers a user using Goole's OAuth.
     */
    public function connectAction(Request $request)
    {
        if($request->query->has('state') && $request->query->has('code'))
        {
            if($request->query->get('state') == $request->getSession()->get('state'))
            {
                $code = $request->query->get('code');
                $google = $this->readConfig();
                $client_id = $google['client_id'];
                $client_secret = $google['client_secret'];
                $redirect_uri = $google['redirect_uri'];

                $otoken = $this->getOAuthToken($code, $client_id, $client_secret, $redirect_uri);
                $google_user = $this->getGoogleUser($otoken);

                $this->findUpdateUser($google_user, $otoken);

                $this->fireLogin();

                // Here, $provider_key is the name of the firewall in your security.yml
                $provider_key = $this->container->getParameter('fos_user.firewall_name'); //$auth['firewall_name'];
                $token = new PreAuthenticatedToken($user, $user->getPassword(), $provider_key, $user->getRoles());
                $this->get("security.context")->setToken($token);

                // Fire the login event
                // Logging the user in as above doesn't do this automatically
                $event = new InteractiveLoginEvent($request, $token);
                $this->get("event_dispatcher")->dispatch("security.interactive_login", $event);
            } else {
                return new Response('Invalid request', 401, array('content-type' => 'text/html'));
            }
        } else {		
            return new Response('Invalid request', 401, array('content-type' => 'text/html'));
        }
        return $this->redirect($this->generateUrl('google_after_login'));
    }

    /**
     * Load parameters from the config.yml file, and caches it for further use.
     */
    private function readConfig()
    {
        if($this->config == null)
            $config = $this->container->getParameter('mlbo_auth');
        return $config['google'];
    }

    /**
     * Gets a token from Google OAuth.
     */
    private function getOAuthToken($code, $client_id, $client_secret, $redirect_uri)
    {
        $encoded = 'code='.$code
                  .'&client_id='.$client_id
                  .'&client_secret='.$client_secret
                  .'&redirect_uri='.urlencode($redirect_uri)
                  .'&grant_type=authorization_code';
        $ch = curl_init('https://accounts.google.com/o/oauth2/token');
        curl_setopt($ch, CURLOPT_POSTFIELDS,  $encoded);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
        curl_close($ch);
        $result = json_decode($result, true);

        if(array_key_exists('error', $result))
        {
            throw new AccessDeniedException($result['error']);
        }

        return array(
            'access_token' => $result['access_token'],
            'id_token' => $result['id_token']
        );
    }

    private function getGoogleUser($token)
    {
        $ch = curl_init('https://www.googleapis.com/userinfo/v2/me');
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Host: www.googleapis.com', 'Authorization: Bearer '.$token['access_token'], 'Content-length: 0'));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
        curl_close($ch);
        return json_decode($result, true);
    }

    private function findUpdateUser($google_user, $otoken)
    {
        $userManager = $this->container->get('fos_user.user_manager');
        $user = $userManager->findUserBy(array('email' => $google_user['email']));
        if($user == null)
        {
            $user = $userManager->createUser();
            $user->setPassword('');
        }

        $user->setUserName($google_user['name']);
        $user->setEmail($google_user['email']);
        $user->setGoogleId($google_user['id']);
        $user->setGoogleAccessToken($otoken['access_token']);
        $userManager->updateUser($user, true);
    }
}
