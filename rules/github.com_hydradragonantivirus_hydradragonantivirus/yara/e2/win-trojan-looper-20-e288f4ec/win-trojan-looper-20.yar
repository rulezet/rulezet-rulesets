rule Win_Trojan_Looper_20
{
strings:
	$a0 = { 406563686f206f6666207265736964656e742e626174 }


condition:
	$a0
}