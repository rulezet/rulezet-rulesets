rule catch_intelligence_files
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	date = "21/09/2015"
    description = "catch files"
strings:
    $meta1 = "National Security Agency"
    $meta3 = "Israeli Secret Intelligence"
    $tag1 = "docx"
	$tag2 = "doc"
	$tag3 = "xls"
	$tag4 = "xlxs"
	$tag5 = "pdf"
	$tag6 = "zip"
	$tag7 = "rar"
    $tag8 = "xlsb"

condition:
    any of ($meta*) and any of ($tag*)
}