rule Win_Trojan_Ramones_1
{
strings:
	$a0 = { 0bc0744fb4ff32dbcd13b802faba4559cd16b419cd1380fcf07429b80102bb0003b10151ba8000cd132681bfe301 }


condition:
	$a0
}