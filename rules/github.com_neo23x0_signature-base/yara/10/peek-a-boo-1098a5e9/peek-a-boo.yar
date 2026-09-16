rule peek_a_boo {
	meta:
		description = "Webshells Auto-generated - file peek-a-boo.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "aca339f60d41fdcba83773be5d646776"
		id = "f6ca33b5-e37f-5124-a193-a3056c559314"
	strings:
		$s0 = "__vbaHresultCheckObj"
		$s1 = "\\VB\\VB5.OLB"
		$s2 = "capGetDriverDescriptionA"
		$s3 = "__vbaExceptHandler"
		$s4 = "EVENT_SINK_Release"
		$s8 = "__vbaErrorOverflow"
	condition:
		all of them
}