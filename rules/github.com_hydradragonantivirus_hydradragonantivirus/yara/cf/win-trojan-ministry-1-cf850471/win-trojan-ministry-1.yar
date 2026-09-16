rule Win_Trojan_Ministry_1
{
strings:
	$a0 = { 018a24b9550481c62e008bfeac32c4aa }


condition:
	$a0
}