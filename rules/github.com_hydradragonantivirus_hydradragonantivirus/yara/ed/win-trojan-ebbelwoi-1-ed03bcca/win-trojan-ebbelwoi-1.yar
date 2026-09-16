rule Win_Trojan_Ebbelwoi_1
{
strings:
	$a0 = { 87fe5d87f78d761de80200eb108a968a01b96d018bfeac32c2aae2fac3 }


condition:
	$a0
}