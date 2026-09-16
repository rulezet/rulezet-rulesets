rule Explosion_Sample_2 {
	meta:
		description = "Explosion/Explosive Malware - Volatile Cedar APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/5vYaNb"
		date = "2015/04/03"
		score = 70
		hash = "62fe6e9e395f70dd632c70d5d154a16ff38dcd29"
		id = "8be7ed50-0bfc-5302-b4fa-8817bf1750d7"
	strings:
		$s0 = "serverhelp.dll" fullword wide
		$s1 = "Windows Help DLL" fullword wide
		$s5 = "SetWinHoK" fullword ascii
	condition:
		all of them and
        uint16(0) == 0x5A4D
}