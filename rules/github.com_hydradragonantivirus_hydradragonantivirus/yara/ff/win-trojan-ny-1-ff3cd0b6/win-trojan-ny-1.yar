rule Win_Trojan_NY_1
{
strings:
	$a0 = { 515256571e06e800005e81ee0b00b8003033dbcd213c037234fafcb8cc33cd213d33cc751c86fb32fb061e568ec3 }


condition:
	$a0
}