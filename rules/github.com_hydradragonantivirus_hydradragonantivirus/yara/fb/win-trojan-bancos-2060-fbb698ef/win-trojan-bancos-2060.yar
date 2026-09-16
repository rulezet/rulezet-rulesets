rule Win_Trojan_Bancos_2060
{
strings:
	$a0 = { 57b1c3d1f696723c148a7f96b4df1ee19ba712ba7f42e46c247d8fbcbae2431ebdac38cd82c39dbde6802bd5a840cb01ca12c3a82846f025866fffd89abc02def4745ca6c8a6f42e5312bc7ff532 }


condition:
	$a0
}