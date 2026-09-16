rule Win_Trojan_Agent_34719
{
strings:
	$a0 = { b87ce24e005064ff35000000006489250000000033c089086a32d823c28bbc76a28300e0cd56bb7c4c }


condition:
	$a0
}