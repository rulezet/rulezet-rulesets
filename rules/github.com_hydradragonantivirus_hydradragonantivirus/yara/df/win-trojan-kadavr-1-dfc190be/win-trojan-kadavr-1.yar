rule Win_Trojan_Kadavr_1
{
strings:
	$a0 = { 576d6322ced284a09ba9e1f0dc19c96c83edcce9632fa7612fc964b3ec6c04cce85ba522ceec2c61 }


condition:
	$a0
}