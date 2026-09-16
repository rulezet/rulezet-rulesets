rule Win_Trojan_Ratboy_9
{
strings:
	$a0 = { 8d96e401b41acd21b44eb93f008d96d001cd217202eb08ba8000b41acd21c3 }


condition:
	$a0
}