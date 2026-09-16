rule Win_Downloader_Delf_182
{
strings:
	$a0 = { 657274732f736f66742f31322e65786500ffffffff0c000000697a78637a7863722e }


condition:
	$a0
}