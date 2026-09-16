rule Win_Downloader_Banload_585
{
strings:
	$a0 = { cc784e6c522074f8e012b66b4e95f8ecd2bdd81f7dc1521c1206231257adae2cada120e80c1f41b5b91144b37f6d46c80a50da90be20b1247d73014ddf11b16c8e1374c0 }


condition:
	$a0
}