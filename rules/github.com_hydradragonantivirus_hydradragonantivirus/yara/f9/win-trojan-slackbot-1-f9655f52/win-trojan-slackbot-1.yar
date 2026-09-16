rule Win_Trojan_Slackbot_1
{
strings:
	$a0 = { ed0425ffa7faf0fafcf9eda7ecf1ec94ad2a84410db7cbff5f736c61636b626f742076312e306231043f3feeffff671a6572726f7220757067726164696e6700636c6f7307ecffc9 }


condition:
	$a0
}