rule Win_Trojan_Mybot_288
{
strings:
	$a0 = { 6e74666d3a2f4156454eed3e32fc534849454c44676f635d8463d74e90134e62 }


condition:
	$a0
}