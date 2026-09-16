rule Explosive_EXE : APT {
	meta:
		description = "Explosion/Explosive Malware - Volatile Cedar APT"
		author = "Check Point Software Technologies Inc."
		id = "3a9fb6b2-2f19-5d70-81ed-a08c3b8b2d80"
	strings:
		$DLD_S = "DLD-S:"
		$DLD_E = "DLD-E:"
	condition:
		all of them and
        uint16(0) == 0x5A4D
}