rule Win_Downloader_Banload_1081
{
strings:
	$a0 = { d0f0617b9b471c70ed385a7349b608e2bdd4f5300cabcc92777309f4701c43e5e9d7051ec4a47bd2c7c25dee84a28827b9afc6f4931386 }


condition:
	$a0
}