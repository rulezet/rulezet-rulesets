rule Win_Trojan_Sterculius_10
{
strings:
	$a0 = { 740db90400ba5c028bf2896c01eb06b91800ba8803b440e8ecfeb43ee8e7fe9d }


condition:
	$a0
}