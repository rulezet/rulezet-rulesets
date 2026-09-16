rule Win_Trojan_AmazonQueen_8
{
strings:
	$a0 = { b440ba0002b9fb0190cd38e8230059b4408bd6cd38b80057cd3840cd38b43ecd38e81c00 }


condition:
	$a0
}