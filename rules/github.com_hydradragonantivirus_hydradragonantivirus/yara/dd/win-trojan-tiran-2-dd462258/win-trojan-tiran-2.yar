rule Win_Trojan_Tiran_2
{
strings:
	$a0 = { 8d961201e87300b9b603cd21b800422bc92bd2cd21b440b90d008d962d03cd21b801578b8e5f }


condition:
	$a0
}