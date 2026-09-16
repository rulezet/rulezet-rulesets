rule Win_Trojan_Faker_1
{
strings:
	$a0 = { 494d20446f776e6c6f61646572[0-3]474554[0-209]446f776e6c6f616465722e4c6f67[0-50]6f70656e }


condition:
	$a0
}