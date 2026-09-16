rule RAT_ClientMesh
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net> (slightly modified by Florian Roth to improve performance)"
		date = "01.06.2014"
		description = "Detects ClientMesh RAT"
		reference = "http://malwareconfig.com/stats/ClientMesh"
		family = "torct"

		id = "351df33e-d3a1-5fe8-be38-edb43bc5d38f"
	strings:
		$string1 = "machinedetails"
		$string2 = "MySettings"
		$string3 = "sendftppasswords"
		$string4 = "sendbrowserpasswords"
		$string5 = "arma2keyMass"
		$string6 = "keylogger"

	condition:
		all of them
}