import "pe"
rule Check_OutputDebugStringA_iat
{

	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "Detect in IAT OutputDebugstringA"
		Date = "20/04/2015"

	condition:
		pe.imports("kernel32.dll","OutputDebugStringA")
}