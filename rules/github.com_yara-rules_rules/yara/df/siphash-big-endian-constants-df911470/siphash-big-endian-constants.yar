rule SipHash_big_endian_constants {
    meta:
		author = "spelissier"
		description = "Look for SipHash constants in big endian"
		date = "2020-07"
		reference = "https://131002.net/siphash/siphash.pdf#page=6"
	strings:
		$c0 = "uespemos"
		$c1 = "modnarod"
		$c2 = "arenegyl"
		$c3 = "setybdet"
	condition:
		2 of them
}