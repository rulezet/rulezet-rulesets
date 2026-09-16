rule Win_Trojan_Janet_1
{
strings:
	$a0 = { 02e81000be3e00bf3003b91000f3a67514e99100bd0400b80102cd13732a33c0cd134d75f2 }


condition:
	$a0
}