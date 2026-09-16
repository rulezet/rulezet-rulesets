rule Win_Downloader_Agent_32870
{
strings:
	$a0 = { f7e8f40f342a3aa69c9ec8a47f80888ff14d97714b86d4ff06708a02f519ebaa74dff1a52c537ec346e327fa02b7c878c9dc6a34a6f75b97ba7cac4c96f5 }


condition:
	$a0
}