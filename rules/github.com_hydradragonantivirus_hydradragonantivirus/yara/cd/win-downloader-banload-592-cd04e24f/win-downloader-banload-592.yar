rule Win_Downloader_Banload_592
{
strings:
	$a0 = { c52a6bba1555eb7159af6f5589880ec1fdc441cddffd37408adc0f63593fc19573d523cab859cfcf4c191077016d365f30901dbb671936b1d4b500af728b0291e0ea1bff }


condition:
	$a0
}