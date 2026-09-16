rule Win_Trojan_Brr_1
{
strings:
	$a0 = { 010350b90400cd132e8816bd010e07bebe07bfbe01b94000f3a45831db41cd132ec606bd0100cb }


condition:
	$a0
}