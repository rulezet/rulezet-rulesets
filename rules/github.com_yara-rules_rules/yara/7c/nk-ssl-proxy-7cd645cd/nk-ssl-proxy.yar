rule NK_SSL_PROXY{
meta:
	Author = "US-CERT Code Analysis Team"
	Date = "2018/01/09"
	MD5_1 = "C6F78AD187C365D117CACBEE140F6230"
	MD5_2 = "C01DC42F65ACAF1C917C0CC29BA63ADC"
	Info= "Detects NK SSL PROXY"
	report = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-G.PDF"
	report = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
strings:
	$s0 = {8B4C24088A140880F24780C228881408403BC67CEF5E}
	$s1 = {568B74240C33C085F67E158B4C24088A140880EA2880F247881408403BC67CEF5E}
	$s2 = {4775401F713435747975366867766869375E2524736466}
	$s3 = {67686667686A75797566676467667472}
	$s4 = {6D2A5E265E676866676534776572}
	$s5 = {3171617A5853444332337765}
	$s6 = "ghfghjuyufgdgftr"
	$s7 = "q45tyu6hgvhi7^%$sdf"
	$s8 = "m*^&^ghfge4wer"
condition:
	($s0 and $s1 and $s2 and $s3 and $s4 and $s5) or ($s6 and $s7 and $s8)
}