rule Win_Downloader_Swizzor_315
{
strings:
	$a0 = { a75b40ff7f6ae80f346faaadc23001ea6cfd88e4451c6f082da82d43caacb760dc87cb03a756dc9d9e399c3613e29dc1d6b02faec2215879cc0012e45462b3c4b8ef5da2ace28261106e0779 }


condition:
	$a0
}