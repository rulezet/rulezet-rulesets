rule Win_Trojan_S_3
{
strings:
	$a0 = { 88261900a11d00a32100a11b00a32300c7061b000000 }


condition:
	$a0
}