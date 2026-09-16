rule Win_Downloader_61388_1
{
strings:
	$a0 = { 6a606818fa4100e80a016accbf940000008bc7e80a015f0c8965e88bf4893e56ff15d4f041008b4e1089 }


condition:
	$a0
}