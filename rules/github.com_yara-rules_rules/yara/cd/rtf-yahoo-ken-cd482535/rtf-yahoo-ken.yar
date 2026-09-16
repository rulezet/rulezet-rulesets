rule rtf_yahoo_ken
{
meta:
	author = "@patrickrolsen"
	maltype = "Yahoo Ken"
	filetype = "RTF"
	version = "0.1"
	description = "Test rule"
	date = "2013-12-14"
strings:
	$magic1 = { 7b 5c 72 74 30 31 } 	$magic2 = { 7b 5c 72 74 66 31 } 	$magic3 = { 7b 5c 72 74 78 61 33 } 	$author1 = { 79 61 68 6f 6f 20 6b 65 63 } condition:
	($magic1 or $magic2 or $magic3 at 0) and $author1
}