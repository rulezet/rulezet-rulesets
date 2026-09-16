rule Win_Trojan_VGEN_309
{
strings:
	$a0 = { 0dcd2133ff8edfb7024fb8024acd2fbb060047750a833e2a03ff752ebf00f9e8cefff32ea4b85c028747fe50ff378c }


condition:
	$a0
}