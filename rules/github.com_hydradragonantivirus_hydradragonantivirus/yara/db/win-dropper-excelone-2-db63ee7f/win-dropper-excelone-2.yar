rule Win_Dropper_Excelone_2
{
strings:
	$a0 = { 9b64bc033b3531f0f93ef0a629c3024f4c311a387cda59c57047add19d0e8e76cbb96da9f943282ae676a39629a3326810532420d975d024ec93af4da21ef1ae }


condition:
	$a0
}