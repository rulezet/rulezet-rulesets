rule Equation_Kaspersky_GreyFishInstaller {
	meta:
		description = "Equation Group Malware - Grey Fish"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "58d15d1581f32f36542f3e9fb4b1fc84d2a6ba35"
		id = "ea16b51c-755e-5f08-a209-d21a1ed30fcf"
	strings:
		$s0 = "DOGROUND.exe" fullword wide
		$s1 = "Windows Configuration Services" fullword wide
		$s2 = "GetMappedFilenameW" fullword ascii
	condition:
		all of them
}