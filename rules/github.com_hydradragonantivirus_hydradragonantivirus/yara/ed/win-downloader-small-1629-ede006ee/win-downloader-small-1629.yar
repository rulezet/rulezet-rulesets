rule Win_Downloader_Small_1629
{
strings:
	$a0 = { 678b238409893369699c58632c9c3f840ee4734184143c0985bd08e90ded3df125900fe9058d26e9 }


condition:
	$a0
}