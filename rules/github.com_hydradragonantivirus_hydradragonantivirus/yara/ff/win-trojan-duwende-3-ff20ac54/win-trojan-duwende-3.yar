rule Win_Trojan_Duwende_3
{
strings:
	$a0 = { 9673af759d8d9608afc06e83720d238fb29d964daf837695238f5850bb0d59757f8f5930ee94713d2f75078d9647af75 }


condition:
	$a0
}