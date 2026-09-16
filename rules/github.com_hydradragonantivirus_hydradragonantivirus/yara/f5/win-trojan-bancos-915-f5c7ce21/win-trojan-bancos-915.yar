rule Win_Trojan_Bancos_915
{
strings:
	$a0 = { 6f05931d601d44778598601b303bcbb4c8e01800ba40a1b70dc2ed0dde480aecee00ae42e4761d3f273102b413b8ecd7596fbdb926e7112a68a7a09db8eaeff3cbfff9eef8f6953affa4c46ca043 }


condition:
	$a0
}