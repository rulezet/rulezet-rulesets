rule Win_Trojan_Pinworm_2
{
strings:
	$a0 = { c100e82201ba4909b92e0a020e4809b440cd21e80101582d0300a32308ba2208b90400b440cd21 }


condition:
	$a0
}