rule Win_Downloader_332_1
{
strings:
	$a0 = { bade8e7cdc26b202bd51da39d6b46b39b5b42d56034c88633e51b7c76aba5b5a2533fd317d7a9103e2e66c71b072f3f85d4df0da15b467d342fadf9bfdf5b3db47da4dd8ab3c9e35ae70b07de03ca05d03d3a72d }


condition:
	$a0
}