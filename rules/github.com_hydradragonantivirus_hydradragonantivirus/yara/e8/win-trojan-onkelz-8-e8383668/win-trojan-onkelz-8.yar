rule Win_Trojan_Onkelz_8
{
strings:
	$a0 = { e800005d81ed09018db62901e80400eb1208008b961701b9fa018bfeac32c2aae2fac3 }


condition:
	$a0
}