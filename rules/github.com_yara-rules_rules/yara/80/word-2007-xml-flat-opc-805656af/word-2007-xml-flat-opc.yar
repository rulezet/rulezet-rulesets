rule Word_2007_XML_Flat_OPC : maldoc
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect Word 2007 XML Document in the Flat OPC format w/ embedded Microsoft Office 2007+ document"
		date = "2018-04-29"
		reference = "https://blogs.msdn.microsoft.com/ericwhite/2008/09/29/the-flat-opc-format/"
		hash1 = "060c036ce059b465a05c42420efa07bf"
		hash2 = "2af21d35bb909a0ac081c2399d0939b1"
		hash3 = "72ffa688c228b0b833e69547885650fe"
		filetype = "Office documents"
		
	strings:
		$xml = "<?xml" 		$WordML = "<?mso-application progid=\"Word.Document\"?>" 		$OPC = "<pkg:package" 		$xmlns = "http://schemas.microsoft.com/office/2006/xmlPackage" 		$binaryData = "<pkg:binaryData>0M8R4KGxGuE" 		$docm = "pkg:name=\"/word/vbaProject.bin\"" 		
	condition:
	 	$xml at 0 and $WordML and $OPC and $xmlns and $binaryData and $docm
}