rule MurmurHash3_Constants {
	meta:
		author = "_pusher_"
		description = "Look for MurmurHash3 constants"
		date = "2017-05"
		version = "0.1"
	strings:
		$c0 = { 512D9ECC }
		$c1 = { 9335871B }
				$c2 = { 6BCAEB85 }
		$c3 = { 35AEB2C2 }
	condition:
		all of them
}