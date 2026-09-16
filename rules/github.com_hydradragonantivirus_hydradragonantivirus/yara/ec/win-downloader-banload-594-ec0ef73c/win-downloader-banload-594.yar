rule Win_Downloader_Banload_594
{
strings:
	$a0 = { 95f5ba332d7bb0039439d5dabe55624971e86d44b2abe872dc1292fb0c28da04ff32716d5b52eafe514e99e5dd79e0213dd265ce6bf307810140c63ea7bf2b5bdf119712 }


condition:
	$a0
}