import "pe"
rule Nalpeiron_License_Manager
{
	meta:
		author="_pusher_"
		date = "2016-09"
		description = "www.nalpeiron.com"
	condition:
		(
		pe.exports("NSAAppStart") and pe.exports("NSAAppStop") and pe.exports("NSLGetComputerID") 
		and ( pe.exports("NSLGetLicenseStatus") or pe.exports("NSLGetFeatureStatus") )
		) or
		(
		pe.exports("CheckLicense") and pe.exports("CheckFlags") and pe.exports("InternetActivate")
		and pe.exports("ReturnLicense") and pe.exports("ReturnVersion")
		)
}