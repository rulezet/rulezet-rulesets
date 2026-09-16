rule Win_Downloader_VB_408
{
strings:
	$a0 = { 07c5e17169e8f3cf206de5aa57eb2b3a1e1e6135a7439f9de01f0fc85e03e6124262e64a9c90afc61dc52d3f13dde73188b31f632a7304ab91a152453ff7487718 }


condition:
	$a0
}