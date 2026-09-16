rule Win_Downloader_Delf_1148
{
strings:
	$a0 = { cb7adda15471ac9b884de153ebee0ad6c314b3984cdffcd7b6d255b671d2a885ad1985dcb0b356163bad5e38a9b7b2406f5f38bd0f3201f89edc44dbfb49b0077517a93803ecda4671869b7977670fc760 }


condition:
	$a0
}