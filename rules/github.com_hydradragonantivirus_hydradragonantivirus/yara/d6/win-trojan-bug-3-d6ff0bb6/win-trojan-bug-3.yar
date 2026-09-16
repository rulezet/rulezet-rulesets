rule Win_Trojan_Bug_3
{
strings:
	$a0 = { 018b052d02008bf08a849904bb280103deb971038a2732e08827434983f90075f3 }


condition:
	$a0
}