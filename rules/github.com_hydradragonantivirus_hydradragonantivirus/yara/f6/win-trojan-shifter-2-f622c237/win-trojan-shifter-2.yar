rule Win_Trojan_Shifter_2
{
strings:
	$a0 = { 8ed8a184002ea38203a186002ea38403a1bc002ea38903a1be002ea38b031fb8adfee858023d0dd0750733c08ed8eb4e908cd8488ed8812e0300800081 }


condition:
	$a0
}