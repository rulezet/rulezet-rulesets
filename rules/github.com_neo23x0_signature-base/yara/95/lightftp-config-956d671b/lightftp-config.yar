rule LightFTP_Config {
	meta:
		description = "Detects a light FTP server - config file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash = "ce9821213538d39775af4a48550eefa3908323c5"
		id = "02ee1d04-1425-5dfd-9b9a-cd378aeda311"
	strings:
		$s2 = "maxusers=" wide
		$s6 = "[ftpconfig]" fullword wide
		$s8 = "accs=readonly" fullword wide
		$s9 = "[anonymous]" fullword wide
		$s10 = "accs=" fullword wide
		$s11 = "pswd=" fullword wide
	condition:
		uint16(0) == 0xfeff and filesize < 1KB and all of them
}