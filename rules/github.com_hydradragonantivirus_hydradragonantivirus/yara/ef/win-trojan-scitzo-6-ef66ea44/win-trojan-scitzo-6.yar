rule Win_Trojan_Scitzo_6
{
strings:
	$a0 = { 03012ea30100b440ba8d012bd180c103cd21b44033d2b98d01cd2158c604e989440132c0e80eff }


condition:
	$a0
}