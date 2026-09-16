rule CN_Honker_Webshell_picloaked_1 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file 1.gif"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3eab1798cbc9ab3b2c67d3da7b418d07e775db70"
		id = "2ff44c4a-ed97-5635-9926-8d54a8364fab"
	strings:
		$s0 = "<?php eval($_POST[" ascii 
		$s1 = ";<%execute(request(" ascii 
		$s3 = "GIF89a" fullword ascii 
	condition:
		filesize < 6KB and 2 of them
}