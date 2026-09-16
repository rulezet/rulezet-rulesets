rule Win_Downloader_Banload_944
{
strings:
	$a0 = { 4011f898ec650586a44a1bad301f75d4bbb45a2c9f21ca43d00fd48376771da9e6956e497c46243d4ca30d04e5634b271fff5d9eea9d3a8629e4857e831e8dc0a7d90ac9dedc13bb4577f27329b1 }


condition:
	$a0
}