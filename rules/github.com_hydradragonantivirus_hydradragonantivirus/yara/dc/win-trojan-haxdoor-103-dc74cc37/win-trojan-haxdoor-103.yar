rule Win_Trojan_Haxdoor_103
{
strings:
	$a0 = { a95d181b986427005b29e9ee168480c201a821fdcfb302adf1bad9b2c00416004b55b8af2788ea6f1c7fd59d00cea640461eb3f26e0f81cbe5c3003861db86630f96e6ca }


condition:
	$a0
}