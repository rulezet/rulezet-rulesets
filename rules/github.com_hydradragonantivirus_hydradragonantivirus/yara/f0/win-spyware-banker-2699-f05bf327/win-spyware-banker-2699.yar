rule Win_Spyware_Banker_2699
{
strings:
	$a0 = { 61f56ffbe105deabc257c7ae7abbbecf23c4cff739e306939e5d043ad248d2bc52d922aaf9d5c2066b0266cd398c9ca3e1ac456faa3c49be20d8d94867ff75ce3b9f7d908652b2d3565265d9ea7e }


condition:
	$a0
}