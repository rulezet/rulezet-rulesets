rule Win_Downloader_Small_4732
{
strings:
	$a0 = { 2e45584520524156074d4f4e0aaa74ec0f54494d45520c49705f618e2ae6ac369324d8fbd9cb4b504657 }


condition:
	$a0
}