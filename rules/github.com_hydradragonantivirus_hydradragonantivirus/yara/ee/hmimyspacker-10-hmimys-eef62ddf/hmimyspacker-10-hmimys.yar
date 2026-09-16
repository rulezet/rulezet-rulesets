rule _hmimysPacker_10__hmimys_
{
	meta:
		description = "hmimys-Packer 1.0 -> hmimys"
	strings:
		$0 = {5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07}
	condition:
		$0
}