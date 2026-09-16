rule Win_Downloader_VB_397
{
strings:
	$a0 = { 4e3d27f6773cdcff6cba3e7710c75fd9ae78bf92dd731effcffc2af56f9a919092455e45cf7facbdf6e267374cf4fc9900f2c66587162bbd280d46236999b2e5a5 }


condition:
	$a0
}