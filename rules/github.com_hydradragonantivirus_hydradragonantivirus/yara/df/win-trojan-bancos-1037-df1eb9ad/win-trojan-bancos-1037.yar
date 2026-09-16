rule Win_Trojan_Bancos_1037
{
strings:
	$a0 = { 4a9769f94120da20657e7cc8c9d2b836f58ecde1216836b81b2380163819cdbdf51a954745c05bd794c63abae9ec7586db39f1fc391dae786fcaf71f2a31105d }


condition:
	$a0
}