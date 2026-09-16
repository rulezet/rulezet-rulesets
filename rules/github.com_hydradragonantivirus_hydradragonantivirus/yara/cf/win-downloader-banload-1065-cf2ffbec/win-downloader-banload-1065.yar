rule Win_Downloader_Banload_1065
{
strings:
	$a0 = { 67ebb710b92410b92b9187ceb3c6a8e7a888ceece4356756c4317511ce16b391351ace6defc9e5eecdffeb848acab716fcdd21c01b02d517848faad0af68943494e95397eb2b2489ca37f6a2359b }


condition:
	$a0
}