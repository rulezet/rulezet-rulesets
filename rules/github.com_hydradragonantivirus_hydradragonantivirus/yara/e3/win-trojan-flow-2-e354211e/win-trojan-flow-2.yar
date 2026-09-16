rule Win_Trojan_Flow_2
{
strings:
	$a0 = { 909090905db906012be980be83020074108a8684028d9e2701b95c01300743e2fb }


condition:
	$a0
}