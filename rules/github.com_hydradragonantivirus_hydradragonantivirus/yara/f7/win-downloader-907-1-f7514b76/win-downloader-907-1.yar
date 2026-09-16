rule Win_Downloader_907_1
{
strings:
	$a0 = { 83c9ff33c0f2aef7d12bf98d5c24148bf78be98bfb83c9fff2ae8bcd4fc1e902f3a58bcd5383e10352f3a4e8e7feffff83c4086a0a53ff1504104000 }


condition:
	$a0
}