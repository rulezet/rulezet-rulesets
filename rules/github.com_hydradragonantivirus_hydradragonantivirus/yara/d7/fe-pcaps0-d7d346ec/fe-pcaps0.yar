rule FE_PCAPs0
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	description = "All pcaps uploaded to VT"
	date = "29/07/2015"
strings:
	$magic = {D4 C3 B2 A1}
condition:
	$magic at 0
}