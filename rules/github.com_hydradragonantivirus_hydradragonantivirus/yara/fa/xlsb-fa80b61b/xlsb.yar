rule xlsb
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Excel Binary Workbook file format detection"

	strings:
		$header = { 50 4B 03 04 }
		$str = "workbook.bin"
	condition:
	   $header at 0 and $str
}