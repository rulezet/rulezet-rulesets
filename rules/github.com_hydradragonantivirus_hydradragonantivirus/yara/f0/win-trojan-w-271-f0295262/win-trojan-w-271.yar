rule Win_Trojan_W_271
{
strings:
	$a0 = { 9cfce8000000005d83ed08b0dcb91d0600008d751b300646e2fb }


condition:
	$a0
}