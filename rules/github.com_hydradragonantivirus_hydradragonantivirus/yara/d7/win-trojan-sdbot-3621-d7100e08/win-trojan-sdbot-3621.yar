rule Win_Trojan_SdBot_3621
{
strings:
	$a0 = { 1064acb28a6eb0416df075a1bd4577f34a5f3fc61f8995e96b6d4af713603e7abb916d12b080a6e4c990e15a656b89dc5f5fbd397816a5536c50e21bdac1eefe85a873ed9d2f2c96b043bf562a06ac71 }


condition:
	$a0
}