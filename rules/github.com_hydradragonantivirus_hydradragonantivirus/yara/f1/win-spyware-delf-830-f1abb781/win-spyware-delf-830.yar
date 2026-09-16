rule Win_Spyware_Delf_830
{
strings:
	$a0 = { e55dc300546f6e674b65794c6f67676572000000ffffffff04000000534d5450 }


condition:
	$a0
}