rule Win_Downloader_Swizzor_553
{
strings:
	$a0 = { fbb030613adcbd3c707a94cb17b9a003a20415611e39fb803f1883387fe3882baa62385aa60a4b1183fdd48a1fdf6cc009d46ca797072418b9adcd9cb6769af73e24de542ff5624d6acf7a6d }


condition:
	$a0
}