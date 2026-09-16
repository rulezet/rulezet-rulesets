rule Win_Spyware_4731_1
{
strings:
	$a0 = { 575f565683c40456893c24538b7c24 }


condition:
	$a0
}