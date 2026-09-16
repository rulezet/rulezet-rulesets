rule Win_Spyware_7296_1
{
strings:
	$a0 = { 60518d0b81c1166c4a2487d95961f97383e80c000000 }


condition:
	$a0
}