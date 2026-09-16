rule Win_Trojan_Andromeda_8
{
strings:
	$a0 = { 5b83eb2053b42acd2180fa05751280fe0a750db000b90d00ba0100bb0001cd26be3412b430 }


condition:
	$a0
}