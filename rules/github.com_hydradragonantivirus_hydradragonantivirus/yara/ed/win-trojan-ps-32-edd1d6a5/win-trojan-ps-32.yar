rule Win_Trojan_PS_32
{
strings:
	$a0 = { b9cf008107000983c302e2f7e8f7005481e415f8b4118d8d5cfbcd188dad88fbb43e99c421af242ccd18064ab8 }


condition:
	$a0
}