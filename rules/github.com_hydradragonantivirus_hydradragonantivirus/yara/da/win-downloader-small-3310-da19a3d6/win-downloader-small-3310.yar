rule Win_Downloader_Small_3310
{
strings:
	$a0 = { 0588007a5eab1d2da67b1925c3c9d9c8bcd00a68cc9a0f1d696dcc49592a3eda6a274d59059f620d9d6d53eb650757499d5140070c8b0b7e680b }


condition:
	$a0
}