rule Win_Downloader_479_1
{
strings:
	$a0 = { 0e169de63a4f9296bfacc25d3f6c9b43a99476e6a818ff1a0ed12ef0c69e6771549cfeb019c6098b1df566bec021c4413b65d0f3a457eb90092bc53c13d96c9dfccfe1bea03c0462bb4024264a16 }


condition:
	$a0
}