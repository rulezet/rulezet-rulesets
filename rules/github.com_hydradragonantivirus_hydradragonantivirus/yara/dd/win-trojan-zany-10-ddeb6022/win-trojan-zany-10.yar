rule Win_Trojan_Zany_10
{
strings:
	$a0 = { b8024233d233c9cd21b4408bd5b9f600cd21b43ecd21c3 }


condition:
	$a0
}