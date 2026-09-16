rule Win_Trojan_ASP_24
{
strings:
	$a0 = { c0fd633a2fbbf2633a5cb6bcbfc9d2d4[0-242]b4edcef3c2b7beb6a3ba5b22266466696c6526225d }


condition:
	$a0
}