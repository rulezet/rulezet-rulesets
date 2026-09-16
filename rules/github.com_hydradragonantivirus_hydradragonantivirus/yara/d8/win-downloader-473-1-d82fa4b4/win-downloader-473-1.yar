rule Win_Downloader_473_1
{
strings:
	$a0 = { 7d0ec804efe7672fabcf58d18ca7e2e3b3678e5dae8a38953705eedb8c707541062beca76bed4232dfe51f73cd4d3af044697ce78173fcfad6935bf10da87d3ca716ddcbd8440d2263652a5b803f }


condition:
	$a0
}