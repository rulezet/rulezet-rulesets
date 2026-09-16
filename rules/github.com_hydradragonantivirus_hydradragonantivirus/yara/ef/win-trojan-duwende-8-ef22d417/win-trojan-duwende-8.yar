rule Win_Trojan_Duwende_8
{
strings:
	$a0 = { 153eef8605f20794fa5470714732b5b1ca89c1c1e999faa7a6bb77aced78042a09edfadba6c7393671c8edb1040507d1 }


condition:
	$a0
}