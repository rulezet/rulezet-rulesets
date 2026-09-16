rule Win_Trojan_Bancos_745
{
strings:
	$a0 = { 0c5c8560baca4e48dc46701d938aaca6804c23c3ba8e8e07d12201915a048b9305a52f6d3c5de83004f9494ad6bff09a74c4b0bef4c0d766112615714f14baa2a21384db }


condition:
	$a0
}