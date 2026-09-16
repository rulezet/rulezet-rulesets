rule Win_Trojan_Small_4075
{
strings:
	$a0 = { 7450e84d00000031ed81c500????fff7dd01dd89ef81c7efdddd1181ef33d6dd11c3bae8????008d041a6a00ff108d8878563412 }


condition:
	$a0
}