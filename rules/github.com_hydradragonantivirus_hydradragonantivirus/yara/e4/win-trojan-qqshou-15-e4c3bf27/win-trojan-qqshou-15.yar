rule Win_Trojan_QQShou_15
{
strings:
	$a0 = { 1fd6947805477ea20bef9e484dc0876fde9544f29cf3fff13b38bec60ca34108484f4526da623160cfb6bd4c34123a55883132285ace52bdc02da4b88fdc }


condition:
	$a0
}