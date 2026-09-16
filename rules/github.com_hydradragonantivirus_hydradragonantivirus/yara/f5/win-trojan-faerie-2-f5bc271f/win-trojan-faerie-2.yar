rule Win_Trojan_Faerie_2
{
strings:
	$a0 = { 860401898617028d960301b91401b440cd2133d233c9b80042cd218d961602b90300b440cd218b }


condition:
	$a0
}