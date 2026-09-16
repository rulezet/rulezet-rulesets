rule Win_Trojan_Vanitas_1
{
strings:
	$a0 = { cefacd213dcefa7503e91501e82f04b88716cd2f0bc0751ebb8001e8bf048cd82e8c9e5b0ce8 }


condition:
	$a0
}