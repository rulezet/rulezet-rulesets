rule Win_Trojan_VCL_2
{
strings:
	$a0 = { 96ff02b8024233c999cd21e4403e88863d01b4408d960301b93b00cd218dbe4403578db63e01 }


condition:
	$a0
}