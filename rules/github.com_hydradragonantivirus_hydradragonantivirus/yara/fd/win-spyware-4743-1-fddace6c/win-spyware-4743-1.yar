rule Win_Spyware_4743_1
{
strings:
	$a0 = { 5568f04a141364ff30648920ba004b1413b8244b1413e8d2f1ffff9090 }


condition:
	$a0
}