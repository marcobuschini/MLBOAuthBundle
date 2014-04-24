# Purpose of this bundle #

<p>I have been very disappointed by the HWIOAuthBundle lately, as it seems its
documentation always lacks some essential step to be configured (at leas with my
main OAuth provider, which is Google). I just wanted a bundle capable of logging
a user in, and registering her, in a very simple way. And this bundle was
born.</p>

# Install the bundle #

<p>At the present moment installation is supported only via git cloning. Create
a path under the <code>vendor</code> directory named
<code>MLB/OAuthBundle</code>, and run the following command inside it:</p>

<pre><code>
$ git clone git://github.com/marcobuschini/MLBOAuthBundle.git .
</code></pre>

<p>That done, you will have to activate the bundle in the
<code>app/AppKernel.php</code> file. Simply add the followin line at the end of
the <code>$bundles</code>:

<pre><code>
new MLB\OAuthBundle\MLBOAuthBundle()
</code></pre>

# Configure the bundle #

<p>First, and foremost you have to properly install, and configure
FOSUserBundle. Get their documentation for that. The minimal configuration
required is as follows (goes to <code>app/config/config.yml</code>):</p>

<pre><code>
fos_user:
    db_driver: orm # other valid values are 'mongodb', 'couchdb' and 'propel'
    firewall_name: main
    user_class: Acme\DemoBundle\Entity\User
</code></pre>

<p>Then we have to configure the OAuth parameters for Google OAuth. Get/set
these from your developer console (goes to:
<code>app/config/config.yml</code>):</p>

<pre><code>
mlbo_auth:
    google:
        client_id: client id
        client_secret: client secret
        redirect_uri: the url we are waiting the server to respond to our request
        scope: https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile
</code></pre>

# Add the table fields #

<p>What follows is an example user entity definition with all the fields
required for running this bundle. In this case we only need the
<code>google_id</code>, and the <code>google_access_token</code> that Google
uses. It's quite simple as it extends the base FOSUserBundle class.</p>

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

# Wire the routing #

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

# Gotchas #

<p>This is a very preliminary work. It suffers from many missing features, and
probably some bugs, too. The most prominent feature missing is the connection
of an already existant user to a Google user. Also, other OAuth providers must
be added.</p>
