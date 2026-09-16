rule Win_Trojan_Pers_1
{
strings:
	$a0 = { 0400b80103cd18bf0002be000068b70159f3a4b80103b90100bb0002cd180761bb007ccd18fb6a }


condition:
	$a0
}