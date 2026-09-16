rule Win_Downloader_Small_3183
{
strings:
	$a0 = { 00822001269b3ed4710440003d7cc73ee00821f4f6c61afd60dce1fe71c3d70c7389decc7791d4fe563ca299be01dc0d778bcdec5599ae7196909a1352f2fc0d77082afde590 }


condition:
	$a0
}