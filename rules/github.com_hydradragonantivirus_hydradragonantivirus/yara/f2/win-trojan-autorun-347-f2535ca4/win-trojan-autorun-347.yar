rule Win_Trojan_Autorun_347
{
strings:
	$a0 = { 5b4175746f52756e5d0d0a4f70656e3d4179616d2d6b616d7075732e6578650d }


condition:
	$a0
}