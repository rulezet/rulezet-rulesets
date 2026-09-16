rule Win_Adware_Virtumonde_12
{
strings:
	$a0 = { 0ebf58f2021abfeaeec5d8fa8dd66d69377d3ca15969c8fea8f20464d56ad7c6161afea3e44c1d3514652fcef06c05b6b38d293631a6d731e6491762102cc5591141ea8d9bb2a6b0955fe54a78b83092 }


condition:
	$a0
}