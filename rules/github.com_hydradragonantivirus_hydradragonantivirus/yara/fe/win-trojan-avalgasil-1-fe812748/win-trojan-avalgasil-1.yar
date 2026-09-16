rule Win_Trojan_Avalgasil_1
{
strings:
	$a0 = { 5e018d74fcb0940e178d64205a32f032d0524444e2f6 }


condition:
	$a0
}