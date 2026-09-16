rule Malicious_SFX1 {
	meta:
		description = "SFX with voicemail content"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
		date = "2015-07-20"
		hash = "c0675b84f5960e95962d299d4c41511bbf6f8f5f5585bdacd1ae567e904cb92f"
		id = "7c29dfb0-bbed-5017-80b4-a5c44024cd70"
	strings:
		$s0 = "voicemail" ascii  
		$s1 = ".exe" ascii
	condition:
		uint16(0) == 0x4b50 and filesize < 1000KB and $s0 in (3..80) and $s1 in (3..80) 
}