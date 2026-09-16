rule Win_Trojan_Sirius_34
{
strings:
	$a0 = { fcbf8100268a4dffb500b020f3ae83f902730ae87000ba8109b409cd21ba3803b409cd2183f901760ab402b20dcd21b2 }


condition:
	$a0
}