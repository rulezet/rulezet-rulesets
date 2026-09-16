rule Win_Downloader_Banload_600
{
strings:
	$a0 = { 2f0b939d092cb2811437e701c37adf4c140a54a24f83e175187787d3b5526d4954ce9827bb8169d17d61f7be76c843cff691e725a025ebfe292ccbd769bd1fba585cf967 }


condition:
	$a0
}