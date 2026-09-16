rule Win_Trojan_Mybot_400
{
strings:
	$a0 = { 77ed80a9af416238c6744c2e3dfc874e494c533e4147415921c469e02e5f1af20002bd7e4f }


condition:
	$a0
}