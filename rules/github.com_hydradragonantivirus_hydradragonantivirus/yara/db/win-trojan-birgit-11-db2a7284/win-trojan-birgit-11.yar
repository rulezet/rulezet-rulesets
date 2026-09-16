rule Win_Trojan_Birgit_11
{
strings:
	$a0 = { 5b53e869feb440b9e7038d960901cd215b53b801573e8b8eb7033e8b96b903cd215bb43ecd21 }


condition:
	$a0
}