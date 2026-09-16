rule WoolenGoldfish_Sample_1 {
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		score = 60
		hash = "7ad0eb113bc575363a058f4bf21dbab8c8f7073a"
		id = "923de51a-8422-5318-95f5-79613d2d642e"
	strings:
		$s1 = "Cannot execute (%d)" fullword ascii
		$s16 = "SvcName" fullword ascii
	condition:
		all of them
}