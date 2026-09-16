rule genericSMS : smsFraud android
{
	meta:
	    	author = "https://twitter.com/plutec_net"
            	reference = "https://koodous.com/"
	    	sample = "3fc533d832e22dc3bc161e5190edf242f70fbc4764267ca073de5a8e3ae23272"
	    	sample2 = "3d85bdd0faea9c985749c614a0676bb05f017f6bde3651f2b819c7ac40a02d5f"

	strings:
		$a = "SHA1-Digest: +RsrTx5SNjstrnt7pNaeQAzY4kc="
		$b = "SHA1-Digest: Rt2oRts0wWTjffGlETGfFix1dfE="
		$c = "http://image.baidu.com/wisebrowse/index?tag1=%E6%98%8E%E6%98%9F&tag2=%E5%A5%B3%E6%98%8E%E6%98%9F&tag3=%E5%85%A8%E9%83%A8&pn=0&rn=10&fmpage=index&pos=magic#/channel"
		$d = "pitchfork=022D4"

	condition:
		all of them
		
}