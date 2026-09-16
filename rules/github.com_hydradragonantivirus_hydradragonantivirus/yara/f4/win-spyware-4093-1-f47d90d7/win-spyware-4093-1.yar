rule Win_Spyware_4093_1
{
strings:
	$a0 = { 68865981242b1c2483c404535b565683c404518bf4c70646189a045e5668 }


condition:
	$a0
}