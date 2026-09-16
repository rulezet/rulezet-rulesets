rule Win_Downloader_Small_1965
{
strings:
	$a0 = { 55682644400064ff30648920b864664000ba34444000e837f4ffff }


condition:
	$a0
}