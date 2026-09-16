rule Win_Trojan_C_2
{
strings:
	$a0 = { fc368b2d83ed034444b8ffa033dbcd2150580681fbffa0741c5058b81f35fec0fec0cd21535b899ea2028c86a40252 }


condition:
	$a0
}