rule Win_Trojan_Octawian_1
{
strings:
	$a0 = { 6f72796f6e20228a79c172c2722664b430906b33f3b20583ec28bfcc33f9920501b3030abf }


condition:
	$a0
}