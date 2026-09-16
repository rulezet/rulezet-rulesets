rule Win_Downloader_Zlob_1539
{
strings:
	$a0 = { cf4fd841710cf8ead416ed623fd7e27632a2576b6e2872dc571d92ae2fc7f05c390442f941850e704d2626c31922ab860d1dd10287403e37eccc047cfc26ca796b9d }


condition:
	$a0
}