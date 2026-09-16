rule Win_Trojan_Hupigon_539
{
strings:
	$a0 = { 4a7e54c55c660228997ed0dd0ea3d5618c8f98a13efc1c9ded9f72451899ba7d796423b82745f493441c40bef5f20b0e5dfd0109f0760cba9cc5dbc68026dd5fdd4d41903daf5b59c50ab8bf8552 }


condition:
	$a0
}