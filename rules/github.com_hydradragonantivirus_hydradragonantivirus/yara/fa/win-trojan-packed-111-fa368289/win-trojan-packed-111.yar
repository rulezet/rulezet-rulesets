rule Win_Trojan_Packed_111
{
strings:
	$a0 = { 3d1354ac3a1d54ac3c6c97a93d0d54ac2d604bbcfa711db4fa691dacfb6112a4fb19125cfb1112543c6c57affb09124c }


condition:
	$a0
}