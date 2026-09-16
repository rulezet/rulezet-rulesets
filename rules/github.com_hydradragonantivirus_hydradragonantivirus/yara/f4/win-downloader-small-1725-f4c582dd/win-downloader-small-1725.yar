rule Win_Downloader_Small_1725
{
strings:
	$a0 = { 2aab016c92520f4c446f77e96c70af7854971aed1d468e687423703a2f886c6966 }


condition:
	$a0
}