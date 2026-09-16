rule Win_Trojan_Gen_194
{
strings:
	$a0 = { 0e0e071f3efe060700bf19f981c73d0880fe8f2aef81e9706e2aeeba99c3d1c218d2bebbd981f627a880e92d84dd }


condition:
	$a0
}