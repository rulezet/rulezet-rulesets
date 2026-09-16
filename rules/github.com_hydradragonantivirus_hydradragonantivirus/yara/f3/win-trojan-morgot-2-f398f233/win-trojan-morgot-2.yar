rule Win_Trojan_Morgot_2
{
strings:
	$a0 = { c70652038400c3b9490390ba00008b1e6e03b440e989feb91c00ba48038b1e6e03b440e97afe }


condition:
	$a0
}