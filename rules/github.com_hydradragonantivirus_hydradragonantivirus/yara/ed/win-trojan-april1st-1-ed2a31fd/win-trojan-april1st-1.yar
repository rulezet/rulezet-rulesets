rule Win_Trojan_April1st_1
{
strings:
	$a0 = { 5907bab3038cdb03d83b1e0200731d83eb20fa8ed3bc0002fb83eb258ec353b9230133ff57be4801fcf3a5cbb409ba }


condition:
	$a0
}