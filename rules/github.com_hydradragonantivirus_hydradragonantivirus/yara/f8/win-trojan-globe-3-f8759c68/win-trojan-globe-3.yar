rule Win_Trojan_Globe_3
{
strings:
	$a0 = { 2e8916d602b430cd218b2e02008b1e2c008edaa3f9238c06f723891ef323892e1324c706fd23ffffe81301c43ef1 }


condition:
	$a0
}