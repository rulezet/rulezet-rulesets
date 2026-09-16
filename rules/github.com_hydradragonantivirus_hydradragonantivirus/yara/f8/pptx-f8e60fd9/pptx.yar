rule pptx
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "PowerPoint 2007 file format detection"
	strings:
		$header = { 50 4B 03 04 }
		$str = "presentation.xml"
	condition:
	   $header at 0 and $str
}