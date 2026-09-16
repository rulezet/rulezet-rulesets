rule Win_Spyware_Goldun_4
{
strings:
	$a0 = { 03527fcfb5962b311d350d002000000070686f746f2e63686d2e6a706723588b6d062de076bb29ae6c13c4ce4762c53a73fc9b67c961f5ce }


condition:
	$a0
}