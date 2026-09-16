rule Win_Adware_Lop_177
{
strings:
	$a0 = { 57f64d64aa6fbd6c5e8ea868699b4ce612b097f0b7707fdc6fcf92c77e5fb338bf127393e89ce6b0c8ff134ac8d8df0af0ea8d0c06ce91d9c87d5c57 }


condition:
	$a0
}