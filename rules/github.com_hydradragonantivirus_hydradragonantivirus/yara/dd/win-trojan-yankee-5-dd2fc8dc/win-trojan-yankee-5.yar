rule Win_Trojan_Yankee_5
{
strings:
	$a0 = { 7007f32ea4061f53b82135cd218c }


condition:
	$a0
}