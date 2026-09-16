rule Win_Downloader_Banload_773
{
strings:
	$a0 = { 754eb7ec8cf655861a3db04903689fc75b820ef79666dc83efb1beb0d71dd247dd7a767ff188bebb80ad61a238a53ed73ca59cdde084bfbce1972e68c61f6ade }


condition:
	$a0
}