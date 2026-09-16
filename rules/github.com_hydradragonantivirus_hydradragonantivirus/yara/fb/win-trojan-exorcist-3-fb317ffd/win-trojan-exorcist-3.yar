rule Win_Trojan_Exorcist_3
{
strings:
	$a0 = { 3dba9e00cd2193b440b9d400ba0001cd215a59b80157cd21b43eebb0cd21b40952baa101cd21 }


condition:
	$a0
}