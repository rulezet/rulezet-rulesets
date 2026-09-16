rule ppt_xml
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "PowerPoint XML file format detection"
	strings:
		$header = "<?xml"
		$str = "<?mso-application progid=\"PowerPoint.Show\"?>"
	condition:
	   $header at 0 and $str
}