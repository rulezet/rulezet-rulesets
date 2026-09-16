rule Win_Trojan_VCLF_1
{
strings:
	$a0 = { 2421b9eb09b805feebfc80c43bebf4b80335cd21b425ba2d02cd2187d3cd21b8f2f9051000ba355983c210b31080eb10cd16b409ba0502cd21b89999cd2181fb9999 }


condition:
	$a0
}