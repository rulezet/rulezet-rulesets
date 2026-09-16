rule Win_Downloader_Banload_1125
{
strings:
	$a0 = { 04d5a5730709e0214f7b601a5e9be7c20fc023e618a2ed9e3fb29105a5cd95acdd67eadacee6126f9f0e912419bc8bb8329cb7d95e759907ff7c78e5 }


condition:
	$a0
}