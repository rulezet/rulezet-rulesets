rule Win_Downloader_Delf_1086
{
strings:
	$a0 = { aeaf03b110b14b99dabaf678d33c1997fb730f4cfe7bb7e2422f20235bfd3412958b8a6cf55c1142584f1d8229b824c60e9e6fc5cf331c75e25d8ed0d5b8df77f4a432f410cfa7229b824bd6a18fd9cb }


condition:
	$a0
}