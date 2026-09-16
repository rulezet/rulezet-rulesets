rule Win_Trojan_Bancos_963
{
strings:
	$a0 = { 0bfaaa302bcf1e5cfb010df1cdd4995fd5a4716b630a26beb5cc091ed45c8449dce97907c39ee93a4c7e6d41e35f02a4481bf049dd245d9363e69b29581944b7bcea280a863f999128bf53dd17a5dc5deea0 }


condition:
	$a0
}