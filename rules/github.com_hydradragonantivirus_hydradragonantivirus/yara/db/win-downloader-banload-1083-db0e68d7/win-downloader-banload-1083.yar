rule Win_Downloader_Banload_1083
{
strings:
	$a0 = { dfa6bb0ad36ee96ab5bd407b17e26ccd5d343d7ba3bd05d81c52f6f6ad4db7f2803db38663ae5942bb4b83dd77be308589ed4269cac7de }


condition:
	$a0
}