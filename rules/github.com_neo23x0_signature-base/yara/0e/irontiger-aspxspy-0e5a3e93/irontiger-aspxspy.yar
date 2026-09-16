rule IronTiger_ASPXSpy : HIGHVOL
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "ASPXSpy detection. It might be used by other fraudsters"
		reference = "http://goo.gl/T5fSJC"
		id = "3010fcb9-0dbf-59ef-90ce-01d922a95f2d"
	strings:
		$str2 = "IIS Spy" wide ascii
		$str3 = "protected void DGCoW(object sender,EventArgs e)" wide ascii
	condition:
		any of ($str*)
}