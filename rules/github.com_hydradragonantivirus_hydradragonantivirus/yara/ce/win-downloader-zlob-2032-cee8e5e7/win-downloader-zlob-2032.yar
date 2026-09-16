rule Win_Downloader_Zlob_2032
{
strings:
	$a0 = { f3cadf225758a135d23145ac915afab34fe984729f8170e7177f4379cbfc361b4f3caf51f8b4ea8d839ac197eb34539b85ed }


condition:
	$a0
}