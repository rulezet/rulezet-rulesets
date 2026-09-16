rule Win_Spyware_Banker_3027
{
strings:
	$a0 = { 56538b9f14c3e2c790dd08fab0c178d957c7322a48a561b73bd8e84b121094e9e0a77dc46f9d5553ee3cb1e8a4 }


condition:
	$a0
}