rule WildNeutron_Sample_6 {
	meta:
		description = "Wild Neutron APT Sample Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "4bd548fe07b19178281edb1ee81c9711525dab03dc0b6676963019c44cc75865"
		id = "c5d87cad-d1ca-5766-90c1-fc8ecfa3f14f"
	strings:
		$s0 = "mshtaex.exe" fullword wide 
	condition:
		uint16(0) == 0x5a4d and filesize < 310KB and all of them
}