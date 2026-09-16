rule Win_Downloader_Banload_1705
{
strings:
	$a0 = { f2a34fccb28c90b5123859921a8008ac5d12db4fdb7cd1cd7af539feb911988235112544cf842a4715efe1f48529ff2633a50cc9b309b52907a4cfbca1214f1b30b5cda08d40820e1458da5eb199 }


condition:
	$a0
}