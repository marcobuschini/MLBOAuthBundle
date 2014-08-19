# Install the bundle #

<p>A prerequisite for this bundle is FOSUserBundle. This bundle makes use of the
FOSUB infrastructure to integrate with a fully developed User framework.</p>

<p>At the present moment installation is supported only via git cloning. Create
a path under the <code>vendor</code> directory named
<code>MLB/OAuthBundle</code>, and run the following command inside it:</p>

<pre><code>
$ git clone git://github.com/marcobuschini/MLBOAuthBundle.git .
</code></pre>

<p>That done, you will have to activate the bundle in the
<code>app/AppKernel.php</code> file. Simply add (with proper punctuation) the
following line at the end of the <code>$bundles</code>:

<pre><code>
new MLB\OAuthBundle\MLBOAuthBundle()
</code></pre>

Follow the instructions in these guides to set up table fields as well as
proper routing:

 - Google
 - Facebook
 - Twitter (TODO)
