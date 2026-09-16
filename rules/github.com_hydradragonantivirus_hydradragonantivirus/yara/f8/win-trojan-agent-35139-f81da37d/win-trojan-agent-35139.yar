rule Win_Trojan_Agent_35139
{
strings:
	$a0 = { 4d5a0a04b8a52360ea349aab0ea043a8d8928ef2a48e0b95cf49c732cbcb8a4c9c97c81f6072ff6f474fb914ffc72ffa06e72ada1ccfb635fbbe1cf02e707ae795c95c8f5e5899c64a59e13458a1185d }


condition:
	$a0
}