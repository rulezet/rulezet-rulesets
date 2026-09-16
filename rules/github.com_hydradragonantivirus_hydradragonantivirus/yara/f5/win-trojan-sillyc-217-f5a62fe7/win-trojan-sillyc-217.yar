rule Win_Trojan_SillyC_217
{
strings:
	$a0 = { e9a800e896007303eb6a9026a11a0024f0051001a37a03ba7903b905008b1e6c03b440cd21 }


condition:
	$a0
}