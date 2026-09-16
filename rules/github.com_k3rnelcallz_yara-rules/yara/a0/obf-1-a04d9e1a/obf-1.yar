rule obf_1 : agent_tesla 
{
	meta: 
		author= "k3rnelcallz"
		filename= "Holiday_Booking.vbs"
		fileType= "vbs"
				source= "Malwarebazaar"
		sha= "d9dcc750e92090e36769db3f0ed8997a0f68c81ebdaef0f7ad5716735fbabf0c"
		tags= "AgentTesla, Loader"
	
	strings:

				$ps_enc= /\$\w+\s*=\s\[system\.Text\.encoding\]::Unicode\.GetStri/ nocase

				$frag_1= /Call\s\w+\(\"ng\(\[system\.c\"\)/ nocase
		$frag_2= /Call\s\w+\(\"onvert\]::Fromba\"/ nocase

				$iex= /Call\s\w+\(\"iex\s\$\w+\"\)/ nocase

				$net_obj= /\"Wscript\.Ne\"\s&\s\"twork\"/ nocase

		$test1= /\w+\s\w+\s=\s\w+\.\w+\(\"Wscript\.Ne\"\s&\s\"twork\"\)/ nocase
	
	condition:
		uint16(0) != 0x5A4D and filesize < 50KB and 3 of them
}