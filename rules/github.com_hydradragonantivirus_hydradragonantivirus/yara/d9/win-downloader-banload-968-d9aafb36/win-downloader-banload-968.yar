rule Win_Downloader_Banload_968
{
strings:
	$a0 = { 556edd05e294f99dba5e7b2015f27fd6512b1981334081cc653fbbcd80fe169cc63a32b4b3b524e24a5ad6e671f7e0b7c9a758d08a92bed6549be26ebe647f6964de3a2c6c6728eab2030b3327632c82 }


condition:
	$a0
}