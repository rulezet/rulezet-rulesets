rule Win_Trojan_Bancos_977
{
strings:
	$a0 = { e6840a608b3b94eaf4aeb9dc3dc5b6c0551753b5f2ae6df734301e21742ba692d01df43fff3193efef6eff0ff5bd5a69fb1af1db69033a067daa1bb5cf1af22fa4b17ed220c1955d4e230ac4f60422535c4b }


condition:
	$a0
}