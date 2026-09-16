rule Win_Spyware_58988_1
{
strings:
	$a0 = { 558bec81ec3c0c0000568d85f4fcffff575068 }

	$a1 = { 3f47616d653d303126706172613d25 }


condition:
	$a0 and $a1
}