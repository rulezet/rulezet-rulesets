rule Win_Trojan_VGEN_697
{
strings:
	$a0 = { 0d01bb510152b42acd2180fa077402751ab80200b9e703fa99cd26403d050075f8fbb409ba2f03cd21cd1980fa057f }


condition:
	$a0
}