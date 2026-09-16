rule Win_Downloader_Small_1575
{
strings:
	$a0 = { f3a58bc833c083e103f3a4bfb410400083c9fff2aef7d12bf98bf78bfa8bd183c9fff2ae8bca4fc1e902f3a58bca8d85a8fbffff83e10350f3a4e885e6ffff }


condition:
	$a0
}