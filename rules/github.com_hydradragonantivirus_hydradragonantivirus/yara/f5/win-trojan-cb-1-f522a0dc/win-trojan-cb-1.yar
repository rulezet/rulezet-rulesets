rule Win_Trojan_CB_1
{
strings:
	$a0 = { 27068bf2b9d005b43fe8f002720d3b }


condition:
	$a0
}