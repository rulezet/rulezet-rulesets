rule Win_Trojan_Ming_1
{
strings:
	$a0 = { 40b903008d961e03cd21b8024233c999cd21b9f9038d960301b440cd21b801575a59cd21b43ecd }


condition:
	$a0
}