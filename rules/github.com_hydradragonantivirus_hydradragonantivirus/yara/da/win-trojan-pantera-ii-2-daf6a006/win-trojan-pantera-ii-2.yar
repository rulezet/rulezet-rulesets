rule Win_Trojan_Pantera_II_2
{
strings:
	$a0 = { b90100ba80008bdd81ebaa5581c34f04cd138b87fe0186e02be8b94f048bf583c65d8a86df }


condition:
	$a0
}