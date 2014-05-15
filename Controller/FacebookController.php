<?php

namespace MLB\OAuthBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;

/**
  * Controller actions to interface with Facebook's OAuth for user registration, and login.
  */
class FacebookController extends Controller
{
    /**
     * Holds private configuratio data.
     */
    private $config = null;

    /**
     * Logs a user in using Facebook's OAuth
     */
    public function loginAction()
    {
        $facebook = $this->readConfig();

        // Creates an hash, and saves in the session. It will be used in
        // multiple authetication steps.
        $state = hash('sha512', rand(), false);
        $session = $this->getRequest()->getSession();
        $session->set('state', $state);

        // Redirect to the Google Login page.
        $uri = 'https://www.facebook.com/dialog/oauth?'.
               'client_id='.$facebook['client_id'].
               '&response_type=code%20token'.
               '&scope='.urlencode($facebook['scope']).
               '&redirect_uri='.urlencode($facebook['redirect_uri']).
               '&state='.$state;
        return $this->redirect($uri);
    }
	
	/**
	 * Invokes a page that rewrites the URL so we can handle that properly.
	 * Wonder why facebook sends url parameters ecoded in a URL fragment.
	 * Stupid API.
	 */
	public function redirectAction(Request $request)
	{
	    return $this->render(
	        'MLBOAuthBundle:Facebook:redirect.html.twig',
	        array('uri' => $request->getUri()));
	}
	
    /**
     * Registers a user using Facebook's OAuth.
     */
    public function connectAction(Request $request)
    {
        if($request->query->has('state') && $request->query->has('code'))
        {
            if($request->query->get('state') == $request->getSession()->get('state'))
            {
                $code = $request->query->get('code');
                $provider_key = $this->container->getParameter('fos_user.firewall_name');
                $facebook = $this->readConfig();
                $client_id = $facebook['client_id'];
                $client_secret = $facebook['client_secret'];
                $redirect_uri = $facebook['redirect_uri'];

                $otoken = $this->getOAuthToken($code, $client_id, $client_secret, $redirect_uri);
                $facebook_user = $this->getFaceBookUser($otoken);

                $user = $this->findUpdateUser($facebook_user, $otoken);

                $this->fireLogin($user, $request);
            } else {
                return new Response('Invalid request', 401, array('content-type' => 'text/html'));
            }
        } else {
            return new Response('Invalid request', 401, array('content-type' => 'text/html'));
        }

        return $this->redirect($this->generateUrl('facebook_after_login'));
    }

    /**
     * Load parameters from the config.yml file, and caches it for further use.
     */
    private function readConfig()
    {
        if($this->config == null)
            $config = $this->container->getParameter('mlbo_auth');
        return $config['facebook'];
    }

    /**
     * Gets a token from Facebook OAuth.
     */
    private function getOAuthToken($code, $client_id, $client_secret, $redirect_uri)
    {
        $url = 'https://graph.facebook.com/oauth/access_token?'.
                'client_id='.$client_id.
                '&redirect_uri='.urlencode($redirect_uri).
                '&client_secret='.$client_secret.
                '&code='.$code;
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
        curl_close($ch);

        $array = array();
        $response = explode('&', $result);
        foreach($response as $r1)
        {
            $r1 = explode('=', $r1);
            $array[$r1[0]] = $r1[1];
        }

        if(array_key_exists('error', $array))
        {
            return new Response('Invalid request: '.$array['error'], 401, array('content-type' => 'text/html'));
        }

        return $array['access_token'];
    }

    private function getFacebookUser($token)
    {
        $ch = curl_init('https://graph.facebook.com/me?fields=id,name,email&access_token='.$token);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
        curl_close($ch);

        return json_decode($result, true);
    }

    private function findUpdateUser($facebook_user, $otoken)
    {
        $userManager = $this->container->get('fos_user.user_manager');
        $user = $userManager->findUserBy(array('facebook_id' => $facebook_user['id']));
        if($user == null)
        {
            $user = $userManager->createUser();
            $user->setPassword('');
        }

        $user->setUserName($facebook_user['name']);
        $user->setEmail($facebook_user['email']);
        $user->setFacebookId($facebook_user['id']);
        $user->setFacebookAccessToken($otoken['access_token']);
        $userManager->updateUser($user, true);

        return $user;
    }

    private function fireLogin($user, $request)
    {
        // Here, $provider_key is the name of the firewall in your security.yml
        $provider_key = $this->container->getParameter('fos_user.firewall_name'); //$auth['firewall_name'];
        $token = new PreAuthenticatedToken($user, $user->getPassword(), $provider_key, $user->getRoles());
        $this->get("security.context")->setToken($token);

        // Fire the login event
        // Logging the user in as above doesn't do this automatically
        $event = new InteractiveLoginEvent($request, $token);
        $this->get("event_dispatcher")->dispatch("security.interactive_login", $event);
    }
}
