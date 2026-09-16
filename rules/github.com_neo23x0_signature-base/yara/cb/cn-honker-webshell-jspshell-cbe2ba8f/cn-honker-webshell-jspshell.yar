rule CN_Honker_Webshell_jspshell {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jspshell.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "d16af622f7688d4e0856a2678c4064d3d120e14b"
		id = "ff72f94b-1c0a-5615-b35f-35f69c920292"
	strings:
		$s1 = "else if(Z.equals(\"M\")){String[] c={z1.substring(2),z1.substring(0,2),z2};Proce" ascii 
		$s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii 
	condition:
		filesize < 30KB and all of them
}