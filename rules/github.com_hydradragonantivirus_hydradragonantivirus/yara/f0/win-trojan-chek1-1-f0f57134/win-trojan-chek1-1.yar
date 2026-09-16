rule Win_Trojan_Chek1_1
{
strings:
	$a0 = { 446b050301894401b440b91a018bd6cd217222b800422bc92bd2cd21b440b903008bd683c26acd }


condition:
	$a0
}