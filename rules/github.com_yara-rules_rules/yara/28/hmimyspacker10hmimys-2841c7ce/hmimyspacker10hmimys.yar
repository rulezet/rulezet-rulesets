rule hmimysPacker10hmimys
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 }

condition:
		$a0
}