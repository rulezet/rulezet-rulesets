rule Win_Trojan_Ransom_36
{
strings:
	$a0 = { e8ecfbfeffe9933b01006a146868df4400e8373e010033ff897de4 }

	$a1 = { 4bfeffc7455cf668ce4bc745684653b55c8b }


condition:
	$a0 and $a1
}