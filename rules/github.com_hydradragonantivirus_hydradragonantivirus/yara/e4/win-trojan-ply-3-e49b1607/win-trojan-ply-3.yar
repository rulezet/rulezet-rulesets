rule Win_Trojan_Ply_3
{
strings:
	$a0 = { fe048ed890908ec0e99b04e8000ce8310be94608e803099003f5b96e01e9ea09902407e9500790 }


condition:
	$a0
}