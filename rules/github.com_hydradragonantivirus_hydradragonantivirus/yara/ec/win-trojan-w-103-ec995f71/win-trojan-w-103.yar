rule Win_Trojan_W_103
{
strings:
	$a0 = { 5d81ed03011e0e1fb0dc8dbe1901b93409300547e2fb64dce1514a61dd11fdafa368e0ef1511fdaffa64dce1514a3fdd11fdafb068e0ef1511fdafcf64dce1514adbde11 }


condition:
	$a0
}