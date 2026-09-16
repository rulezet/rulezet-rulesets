rule Win_Downloader_Delf_1154
{
strings:
	$a0 = { 7758eb4d97d6efd4945a7b8dcf9e1a3dbd42bf095c4a05ddc59bb9e05af93fa399c8042287393d6fe2c81e97e16ce93a7b9be15e83f89c49c14623b196ede16fb6437164aea159b3851b14edb8b1df96a7 }


condition:
	$a0
}