rule Win_Spyware_4733_1
{
strings:
	$a0 = { 575183c4040f00c75683c4045fe81000000023ccf64a9e54485e7a }


condition:
	$a0
}