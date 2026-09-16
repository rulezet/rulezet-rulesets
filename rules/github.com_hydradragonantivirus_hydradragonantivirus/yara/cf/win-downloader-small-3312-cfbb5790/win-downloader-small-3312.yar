rule Win_Downloader_Small_3312
{
strings:
	$a0 = { fc0bd6f62de45629320c644ab0c753c11338464fcef5bf05d6a3c6ad9c862efeb5398bc28af94cef2b86327e891384773def362d1a4021feb08c }


condition:
	$a0
}