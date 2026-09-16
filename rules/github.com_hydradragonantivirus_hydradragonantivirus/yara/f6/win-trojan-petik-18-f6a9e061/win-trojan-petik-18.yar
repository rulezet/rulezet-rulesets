rule Win_Trojan_Petik_18
{
strings:
	$a0 = { 6578743d22687461226f726578743d2261737022 }

	$a1 = { 676f6f642e[0-9]76697275732e68746d6c74657874 }


condition:
	$a0 and $a1
}