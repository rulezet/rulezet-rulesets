rule Win_Trojan_Paris_3
{
strings:
	$a0 = { 8cd803c38ed88ec08d3e0301b000aa3b }


condition:
	$a0
}