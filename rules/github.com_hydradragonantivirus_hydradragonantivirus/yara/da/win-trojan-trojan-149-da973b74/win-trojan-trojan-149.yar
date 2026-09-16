rule Win_Trojan_Trojan_149
{
strings:
	$a0 = { 0201ff360401b43fb90300ba0201cd21725fa00e0138 }


condition:
	$a0
}