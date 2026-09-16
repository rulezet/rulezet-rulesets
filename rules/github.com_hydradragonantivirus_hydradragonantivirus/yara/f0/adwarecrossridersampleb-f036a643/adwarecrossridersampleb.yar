rule AdwareCrossriderSampleB
{
	meta:
		Description  = "Adware.Crossrider.B.vb"
		ThreatLevel  = "5"

	strings:
		$ = "crossbrowse/updater/{{camp_id}}/{{version}}/{{secret}}/update.json" ascii wide
		$ = "Crossbrowse\\Crossbrowse\\Application\\crossbrowse.exe" ascii wide
		$ = "allnetserveline.com/crossbrowse" ascii wide
		$ = "C:\\workspace\\crossbrowse" ascii wide
		$ = "CrossriderBrowserInstaller.pdb" ascii wide

	condition:
		any of them
}