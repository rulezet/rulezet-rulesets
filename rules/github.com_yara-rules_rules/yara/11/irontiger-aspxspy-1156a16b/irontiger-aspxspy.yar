rule IronTiger_ASPXSpy
{
    
    meta:
        author = "Cyber Safety Solutions, Trend Micro"
        description = "ASPXSpy detection. It might be used by other fraudsters"
        reference = "http://goo.gl/T5fSJC"
   
    strings:
        $str1 = "ASPXSpy" nocase wide ascii
        $str2 = "IIS Spy" nocase wide ascii
        $str3 = "protected void DGCoW(object sender,EventArgs e)" nocase wide ascii
    
    condition:
        any of ($str*)
}