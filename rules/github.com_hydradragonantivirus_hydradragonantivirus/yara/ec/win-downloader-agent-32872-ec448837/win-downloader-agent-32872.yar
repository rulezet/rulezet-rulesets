rule Win_Downloader_Agent_32872
{
strings:
	$a0 = { 499b2b95b58d1c5060b90e8af77c8c0079a92d391fb207bdcedb7fd14e117b3db5092dfd5d1484d49f96271749ff9ecacba7ad9de809cd7f993baf2cb34a }


condition:
	$a0
}