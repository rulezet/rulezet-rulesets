rule Win_Trojan_Vector_1
{
strings:
	$a0 = { 7504b8c0abcf80fc1174c380fc1274be80fc407518 }


condition:
	$a0
}