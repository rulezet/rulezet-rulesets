rule Win_Trojan_Onkelz_5
{
strings:
	$a0 = { 20e800005d81ed09018db62901e80400eb1200008b9617018bfeb9ed01ac32c2aae2fac3 }


condition:
	$a0
}