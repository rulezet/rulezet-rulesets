rule Win_Trojan_RemoteExplorer_1
{
strings:
	$a0 = { d7bcfb41c2936f66fd6dc76e9b7eec91779fe4bff8e87739a766ee5b7afc96918f2e79b3e29e }


condition:
	$a0
}