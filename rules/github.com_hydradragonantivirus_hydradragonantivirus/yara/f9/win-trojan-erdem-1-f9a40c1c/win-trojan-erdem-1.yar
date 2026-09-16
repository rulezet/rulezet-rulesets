rule Win_Trojan_Erdem_1
{
strings:
	$a0 = { 2ea3a702ba0001b9a90190b44180ec01cd2133c933d2b80042cd21baa602b90300b440cd21 }


condition:
	$a0
}