rule Win_Downloader_Small_726
{
strings:
	$a0 = { 746e65722e636f6d2f696e7374616c6c65642e7068 }

	$a1 = { fc11db72edb80100000001db75078b1e83eefc11db11c001db73ef75098b1e83eefc11db73e431c983e803720dc1e0088a064683f0ff }


condition:
	$a0 and $a1
}