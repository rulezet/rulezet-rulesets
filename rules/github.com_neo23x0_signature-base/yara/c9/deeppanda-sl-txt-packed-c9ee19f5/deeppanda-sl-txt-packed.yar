rule DeepPanda_sl_txt_packed {
	meta:
		description = "Hack Deep Panda - ScanLine sl-txt-packed"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015/02/08"
		hash = "ffb1d8ea3039d3d5eb7196d27f5450cac0ea4f34"
		id = "7a335810-2bf9-5a0b-bef4-1bade65a0f00"
	strings:
		$s0 = "Command line port scanner" fullword wide
		$s1 = "sl.exe" fullword wide
		$s2 = "CPports.txt" fullword ascii
		$s3 = ",GET / HTTP/.}" fullword ascii
		$s4 = "Foundstone Inc." fullword wide
		$s9 = " 2002 Foundstone Inc." fullword wide
		$s15 = ", Inc. 2002" fullword ascii
		$s20 = "ICMP Time" fullword ascii
	condition:
		all of them
}