rule Win_Trojan_Hupigon_759
{
strings:
	$a0 = { ce215427619ea0478fd3a7398d3dc58e39c850f7159fb020aa7aa2428b82e07da0da1a7e22fceac9c34c43cc8a562708f1c9449654cdb4fca359a0b87b3024553ba860235b792dc65d74e11ebe4a }


condition:
	$a0
}