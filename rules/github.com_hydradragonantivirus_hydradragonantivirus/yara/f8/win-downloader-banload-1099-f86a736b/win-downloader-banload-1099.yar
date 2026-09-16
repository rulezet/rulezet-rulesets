rule Win_Downloader_Banload_1099
{
strings:
	$a0 = { 36719f3796a1b8be8673a6b55a864843af8d0d59ddedc6d016ec07ba6250c614aff1ccb1cf8d01c45abe53a817750185ddb826bc90ff559e88335428b0d3c56a6c9816ec7233f8 }


condition:
	$a0
}