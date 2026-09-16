rule Win_Trojan_Gergana_2
{
strings:
	$a0 = { 50b41aba80ffcd21b44ebaa50133c9cd217266b8023dba9effcd21720f93b43fb9b600ba00facd217202eb12e80800b44fcd217244ebdcb43ecd21723c }


condition:
	$a0
}