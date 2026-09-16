rule Binary_Drop_Certutil {
	meta:
		description = "Drop binary as base64 encoded cert trick"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/9DNn8q"
		date = "2015-07-15"
		score = 70
		id = "19791e51-d041-524d-80fa-9f3ec54eb084"
	strings:
		$s0 = "echo -----BEGIN CERTIFICATE----- >" ascii
		$s1 = "echo -----END CERTIFICATE----- >>" ascii
		$s2 = "certutil -decode " ascii
	condition:
		filesize < 10KB and all of them
}