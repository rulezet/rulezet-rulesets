rule Win_Trojan_Khizhnjak_40
{
strings:
	$a0 = { 1e8cc805????8ed8b9030033db8a87????2e8887000143e2f4b12032db2e8a8780008887????43e2f4 }


condition:
	$a0
}