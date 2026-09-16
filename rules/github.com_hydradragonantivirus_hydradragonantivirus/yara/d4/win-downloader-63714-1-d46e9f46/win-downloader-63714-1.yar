rule Win_Downloader_63714_1
{
strings:
	$a0 = { 4765726149642e657865 }

	$a1 = { 57696e446b696c6c2e657865 }

	$a2 = { 5c636f6e66696765782e646c6c }


condition:
	$a0 and $a1 and $a2
}