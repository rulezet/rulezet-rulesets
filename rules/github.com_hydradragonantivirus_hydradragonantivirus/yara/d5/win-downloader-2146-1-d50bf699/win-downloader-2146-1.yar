rule Win_Downloader_2146_1
{
strings:
	$a0 = { 687474703a2f2f00cef2fbe9eafceff8c1d0f4feeff2eef2fbe9c1d4f3e9f8eff3f8e9bdd8e5edf1f2eff8efc1c9e4edf8f9c8cfd1ee000065456e74727941007455726c436163680000000046696e644e6578 }

	$a1 = { 7378732e646c6c }


condition:
	$a0 and $a1
}