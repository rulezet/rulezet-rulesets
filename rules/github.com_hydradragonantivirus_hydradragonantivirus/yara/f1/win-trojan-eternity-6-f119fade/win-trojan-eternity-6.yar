rule Win_Trojan_Eternity_6
{
strings:
	$a0 = { e806005d83ed03eb08b8050333dbcd16c3e81400eb24e80f00b440b99a018bd5cd21e80300 }


condition:
	$a0
}