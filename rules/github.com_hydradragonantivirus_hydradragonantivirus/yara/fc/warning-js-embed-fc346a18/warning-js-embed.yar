rule warning_js_embed {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 3
		revision = "1"
		date = "Apr 12 2017"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2017. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Embedded js"
	strings:
		$s1 = {6a 73 00}
		$s2 = "Package"
		$s3 = {2e 00 6a 00 73}
		$s4 = "Ole10Native" wide
	condition:
            3 of them
}