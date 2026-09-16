rule Win_Trojan_Leprosy_30
{
strings:
	$a0 = { 9040e81a00e958018b1e5f0253e80f005bb99a02ba0001b440cd21e80100c3bb34 }


condition:
	$a0
}