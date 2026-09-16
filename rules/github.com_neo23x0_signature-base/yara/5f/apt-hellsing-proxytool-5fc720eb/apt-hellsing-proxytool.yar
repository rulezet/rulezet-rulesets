rule apt_hellsing_proxytool { 
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing proxy testing tool"
		id = "54454f07-11a9-5456-b489-9a9610e53123"
	strings: 
		$a1 = "PROXY_INFO: automatic proxy url => %s"
		$a2 = "PROXY_INFO: connection type => %d"
		$a3 = "PROXY_INFO: proxy server => %s"
		$a4 = "PROXY_INFO: bypass list => %s"
		$a5 = "InternetQueryOption failed with GetLastError() %d"
		$a6 = "D:\\Hellsing\\release\\exe\\exe\\" nocase
	condition:
		uint16(0) == 0x5a4d and (2 of ($a*)) and filesize < 300000
}