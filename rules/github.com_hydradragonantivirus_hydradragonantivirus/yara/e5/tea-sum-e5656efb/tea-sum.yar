rule TEA_SUM {
	meta:
		author = "_pusher_"
		description = "TEA SUM"
		date = "2016-02"
	strings:
		$c0 = { 90 9B 77 E3 }
	condition:
		any of them
}