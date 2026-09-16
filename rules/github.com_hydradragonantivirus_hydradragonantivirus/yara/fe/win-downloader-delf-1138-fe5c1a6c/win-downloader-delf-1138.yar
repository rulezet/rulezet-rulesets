rule Win_Downloader_Delf_1138
{
strings:
	$a0 = { 0864c9c18adfa881d5e6d9f305921d08b7037a97b1e028a968eac47084f2806ff2cbdd065e1bf9e5fe8dfab97cb58b6faceffe65785bfff2cafb26ca8c91c3447a3a635d3e86c75343aac088f79ed7781a }


condition:
	$a0
}