rule Win_Downloader_Banload_280
{
strings:
	$a0 = { 9accf4d49ad403f3bd472e2bfbaf1ed0eaf38e62a38d78c1155ecd8b056dc85ccfd93e1dd6a013caa4945efa8d2b2fc6f917e27ccf86670f0bcb6f80771a372a566b1452b7079c6aac1b7c79de0b }


condition:
	$a0
}