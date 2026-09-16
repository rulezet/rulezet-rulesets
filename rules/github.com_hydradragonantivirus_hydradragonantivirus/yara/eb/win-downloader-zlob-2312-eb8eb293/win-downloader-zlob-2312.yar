rule Win_Downloader_Zlob_2312
{
strings:
	$a0 = { ea0259ca5646ac25eda846f92c75e5d13ffd50bf7c2f73fbcc9b25fd6bb32a3423d2b24df93ff19738265b6594532ad236b061f7a7ccef881b9afe7a40496cec14efdf45df54fa2030f2a458e4b1 }


condition:
	$a0
}