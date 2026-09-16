rule Win_Trojan_SillyC_53
{
strings:
	$a0 = { 0500108ec0be00018bfeb99f00f3a48ed81eb8190150cbba8000b41acd21ba5901b93f00b44ecd217254ba9e00b8 }


condition:
	$a0
}