import "pe"
import "hash"
import "console"
rule Indian_APT_PE_and_String{

	meta :
		Author = "Diyar Saadi"
		Date = "06/07/2024"
		Malware_Nationality = "India"
		Malware_MD5_Hash = "8C095479D9BEBA9ED56BB8D95861686D"

	strings:

		$a1 = "jlitest.dll"
		$a2 = "JLI_AcceptableRelease"
		$a3 = "JLI_FreeManifest"
		$a4 = "JLI_Launch"
		$a5 = "JLI_StringDup"
		$a6 = "JLI_MemAlloc"
		$a7 = "JLI_MemFree"
		$a8 = "JLI_ValidVersionString"
		$pathpdb = "E:\\new_ops\\jlitest __change_ops -29no - Copy\\Release\\jlitest.pdb"

		condition:
			console.log("The SHA256 Hash : ", hash.sha256(0,filesize)) and
			console.hex("The Magic Header : ", uint16(0)) and 
			any of them and
			console.log("PE Indicator : ", pe.is_32bit()) or 
			(pe.timestamp == 1639036360 or pe.export_timestamp == 4294967295  ) and
			(pe.number_of_signatures == 0 or pe.number_of_imports == 3 or pe.number_of_exports == 4) and 
			pe.pdb_path contains "E:\\new_ops\\jlitest"
		
}