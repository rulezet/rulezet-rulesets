rule Win_Spyware_4092_1
{
strings:
	$a0 = { 8b54240483c40881c7da6138355481efda613835893c24eb008b3c24 }


condition:
	$a0
}