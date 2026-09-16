rule Win_Downloader_59738_1
{
strings:
	$a0 = { 73726576697264[0-9]6578652e6c6e5c[0-9]7478742e6c6e5c[0-85]6578652e316565725c }


condition:
	$a0
}