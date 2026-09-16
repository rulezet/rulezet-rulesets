rule bin_ndisk {
	meta:
		description = "Hacking Team Disclosure Sample - file ndisk.sys"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.virustotal.com/en/file/a03a6ed90b89945a992a8c69f716ec3c743fa1d958426f4c50378cca5bef0a01/analysis/1436184181/"
		date = "2015-07-07"
		score = 100
		hash = "cf5089752ba51ae827971272a5b761a4ab0acd84"
		id = "f442315e-67c2-55a5-954e-8e7e48aa1243"
	strings:
		$s1 = "\\Registry\\Machine\\System\\ControlSet00%d\\services\\ndisk.sys" fullword wide 
		$s2 = "\\Registry\\Machine\\System\\ControlSet00%d\\Enum\\Root\\LEGACY_NDISK.SYS" fullword wide 
		$s3 = "\\Driver\\DeepFrz" wide
		$s4 = "Microsoft Kernel Disk Manager" fullword wide 
		$s5 = "ndisk.sys" fullword wide
		$s6 = "\\Device\\MSH4DEV1" wide
		$s7 = "\\DosDevices\\MSH4DEV1" wide
		$s8 = "built by: WinDDK" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and 6 of them
}