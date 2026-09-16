rule Win_Trojan_Vlab_2
{
strings:
	$a0 = { 81ed080183fd00740dbe680201eebf0001b90300f3a4c6865f0200b41aba340201eacd21b44eba600201eacd217233 }


condition:
	$a0
}