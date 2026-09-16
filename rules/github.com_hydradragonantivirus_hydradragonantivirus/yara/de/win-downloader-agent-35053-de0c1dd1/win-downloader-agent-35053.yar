rule Win_Downloader_Agent_35053
{
strings:
	$a0 = { 4c645496b54b014d02f53a71ee9046dc8ddeb16d0a4fe0bf5a80b6f59f0365880b75e6f597b380605121d5e69634362386dc }


condition:
	$a0
}