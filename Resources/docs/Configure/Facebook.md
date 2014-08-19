# Connecting with Facebook #

## Parameters ##
<p>We now have to configure the parameters for Facebook OAuth. Get/set these
from your developer console (goes to: <code>app/config/config.yml</code>):</p>

<pre><code>
# app/config/config.yml

mlbo_auth:
    google:
        client_id: client id
        client_secret: client secret
        redirect_uri: the url we are waiting the server to respond to our request
        scope: https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile
</code></pre>

You must get the <code>redirect_uri</code> from the route named
<code>google_connect</code>. The same URI must be written in the developer
console.

## Add the table fields ##
<p>What follows is an example user entity definition with all the fields
required for running this bundle with Google OAuth. In this case we only need to
store the <code>google_id</code>, and the <code>google_access_token</code> that
Google uses. It's quite simple as it extends the base FOSUserBundle class.</p>

<pre><code>
// src/Acme/DemoBundle/Entity/User.php

namespace Acme\DemoBundle\Entity;

use FOS\UserBundle\Entity\User as BaseUser;
use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Entity
 * @ORM\Table(name="fos_user")
 */
class User extends BaseUser
{
    /**
     * @ORM\Id
     * @ORM\Column(type="integer")
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    protected $id;

    /**
     * @ORM\Column(type="string")
     */
    protected $google_id;

    /**
     * @ORM\Column(type="string")
     */
    protected $google_access_token;

    public function __construct()
    {
        parent::__construct();
        // your own logic
    }

    public function getGoogleId()
    {
        return $this->google_id;
    }

    public function setGoogleId($google_id)
    {
        $this->google_id = $google_id;
    }

    public function getGoogleAccessToken()
    {
        return $this->google_access_token;
    }

    public function setGoogleAccessToken($google_access_token)
    {
        $this->google_access_token = $google_access_token;
    }
}
</code></pre>

## Wire the routing ##

<p>Here are the routes that we have to add to
<code>app/config/routing.yml</code> to have the application be able to login,
and register a new user via this bundle. The <code>google_login</code> route is
used to log a user in (i.e.: it is the entry point for the user). The
<code>google_connect</code> route is invoked by the Google's OAuth servers to
confirm that Google reconizes the user. The <code>google_after_login</code>
route is invoked when the user has logged in successfully.</p>

<pre><code>
google_login:
    path:      /google/login
    defaults:  { _controller: MLBOAuthBundle:Google:login }

google_connect:
    path:      /google/connect
    defaults:  { _controller: MLBOAuthBundle:Google:connect }

google_after_login:
    path:      /welcome
    defaults:  { _controller: AcmeDemoBundle:Welcome:index }
</code></pre>
