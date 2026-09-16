rule Win_Spyware_Banker_2573
{
strings:
	$a0 = { 0dfcc2a09d00a140335476bcd1891254d4540f552060bccbe0597864a7d1a1c950ad2551b6772e78da2abf0c693bc7f81d5471ec4c01eb784aadccb66eb8ddcd629b77d151da0fc68161e90da4db9478 }


condition:
	$a0
}