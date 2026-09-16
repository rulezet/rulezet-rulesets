rule Win_Downloader_Istbar_107
{
strings:
	$a0 = { 2e736c6f7463682e636f6d2fdd74ff7eabfd2f736f667477bc352f76342e3012646f776ea1fdbd6e236164a03f25732025fd5c167b6d3a070b666f3f7bc5bfb0 }


condition:
	$a0
}