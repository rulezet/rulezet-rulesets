rule Win_Trojan_Maniac_1
{
strings:
	$a0 = { 1e0689f781ee000132c088e0b93208bb00002e8a042e30812b002e8a812b004389fe29c64ee2eb }


condition:
	$a0
}