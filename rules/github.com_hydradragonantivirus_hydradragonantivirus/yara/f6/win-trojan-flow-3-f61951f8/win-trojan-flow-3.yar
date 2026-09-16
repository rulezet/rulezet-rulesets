rule Win_Trojan_Flow_3
{
strings:
	$a0 = { 46e2fbb8024233c933d2cd21b440b926008d960301cd21b440b95f018d968802cd21b43ecd21 }


condition:
	$a0
}