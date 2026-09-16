rule Win_Trojan_BB_1
{
strings:
	$a0 = { 7303be39018bfefcad33060301ab49 }


condition:
	$a0
}