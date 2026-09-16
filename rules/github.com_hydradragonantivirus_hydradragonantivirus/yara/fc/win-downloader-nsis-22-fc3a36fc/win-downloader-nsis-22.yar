rule Win_Downloader_NSIS_22
{
strings:
	$a0 = { 737863626c6f672e696e666f3a3737372f756a6d726563616c }

	$a1 = { 61633dfd85802666696c653dfd9080006d61633dfd89802673 }


condition:
	$a0 and $a1
}