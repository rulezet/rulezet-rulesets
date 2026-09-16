rule Win_Downloader_Agent_35046
{
strings:
	$a0 = { 5e1710e240ce65ca822b9cca4f905b12f5d586882eee61c30dc0f7174faab88db8ad92fc07a18ed5db3b2a665c9bbf9a0a9f }


condition:
	$a0
}