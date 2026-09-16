rule Win_Downloader_Small_4942
{
strings:
	$a0 = { b90000f07f8d128b8914000e00 }

	$a1 = { 6e557365724167656e74537472696e670075726c6d6f6e2e646c6c0000000043 }


condition:
	$a0 and $a1
}