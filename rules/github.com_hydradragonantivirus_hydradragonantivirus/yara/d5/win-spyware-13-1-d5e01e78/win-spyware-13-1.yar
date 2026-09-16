rule Win_Spyware_13_1
{
strings:
	$a0 = { 5370792077696c6c20656e64206e6f7710441f52656d6fde737973 }


condition:
	$a0
}