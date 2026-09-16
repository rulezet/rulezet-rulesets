rule Win_Downloader_Banload_598
{
strings:
	$a0 = { 6a94cc9354a9e45268d4fa8af07242158cd78d7df807200ebd6eea332f67ef372a07f63c5edb2efb4ee95387d9b6c23020e9cd92aa23dffb1d9b7fedc70a8d067b81fb84 }


condition:
	$a0
}