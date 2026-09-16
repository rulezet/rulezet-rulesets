rule Win_Trojan_Search_11
{
strings:
	$a0 = { 7efe0075c5817efce80372be817efc50c377b7fc8bfdb0 }


condition:
	$a0
}