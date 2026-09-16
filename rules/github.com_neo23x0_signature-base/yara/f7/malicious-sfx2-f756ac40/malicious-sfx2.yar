rule Malicious_SFX2 {
	meta:
		description = "SFX with adobe.exe content"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
		date = "2015-07-20"
		hash = "502e42dc99873c52c3ca11dd3df25aad40d2b083069e8c22dd45da887f81d14d"
		id = "ff59d638-4d82-5a14-b346-3df2154d3c34"
	strings:
		$s1 = "adobe.exe" fullword ascii  
		$s2 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide  
		$s3 = "GETPASSWORD1" fullword wide  
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}