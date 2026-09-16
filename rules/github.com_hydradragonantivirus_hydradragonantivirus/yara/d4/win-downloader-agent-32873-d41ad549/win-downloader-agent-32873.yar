rule Win_Downloader_Agent_32873
{
strings:
	$a0 = { 65cfae70b099b1754c5662199e41eb7a60681975d3ade538840bcd788a62cec6099afd4694e3e587d4d6b5fad0193b3ca56bfe3c63a98278081f19155021 }


condition:
	$a0
}