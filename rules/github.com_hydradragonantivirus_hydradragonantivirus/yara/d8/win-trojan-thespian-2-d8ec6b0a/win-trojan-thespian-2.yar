rule Win_Trojan_Thespian_2
{
strings:
	$a0 = { 91018d960600cd21e80500b43ecd21c38db61100b96101803447464975f9c3 }


condition:
	$a0
}