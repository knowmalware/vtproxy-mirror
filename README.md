Originally from blog post http://blog.michaelboman.org/2013/09/caching-virustotal-results.html by Michael Boman.

<blockquote>
 Caching VirusTotal results


 I am doing a lot of  VirusTotal lookups from multiple tools in my preparation of the data for my presentation at DEEPSEC 2013 regarding "Malware data-mining and attribution". As you can understand the limitations of the public API key (4 requests/minute) makes the process a bit slow. However, I have managed to create a work-around this issue. And here is how:

 I have written a proxy in python using the Twisted API that cache the results from VirusTotal into a MongoDB database. If the result is already known the requester gets a cached result and skip the request upstream to the VirusTotal servers.

 You can make use of the proxy either by setting the http\_proxy and https\_proxy environment variables, or by changing the script that makes the VirusTotal request to make use of the proxy. Personally I am doing the later, but that's my preference.

 Here is the vtproxy.py code
</blockquote>
