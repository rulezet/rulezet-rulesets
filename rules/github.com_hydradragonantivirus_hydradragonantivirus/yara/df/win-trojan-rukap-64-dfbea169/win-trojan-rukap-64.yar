rule Win_Trojan_Rukap_64
{
strings:
	$a0 = { 0b4eaadad2d497b7a486d5defe398ed0ab13d0c6adc968c3326c06fc85b392782097ffa2021d92f175bcf57d586c0c1f36ec82e2b46233847789e95d6a56eef2927f0851b4333ecf }


condition:
	$a0
}