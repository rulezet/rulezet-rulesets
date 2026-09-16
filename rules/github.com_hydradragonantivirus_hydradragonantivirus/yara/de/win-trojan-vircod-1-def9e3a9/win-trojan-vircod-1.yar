rule Win_Trojan_Vircod_1
{
strings:
	$a0 = { 86005589e5b800029a7c02860081ec0002b00050bf48001e57b8ff00509af90a8600bf09050e579a4a0b86009a }


condition:
	$a0
}