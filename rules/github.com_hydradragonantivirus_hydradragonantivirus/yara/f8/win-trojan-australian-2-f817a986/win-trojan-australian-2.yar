rule Win_Trojan_Australian_2
{
strings:
	$a0 = { 695f96879e949473cd9388d6a6a9a68da699d173619b881dd72c80912d959654b69388a24521d730 }


condition:
	$a0
}