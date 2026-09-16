import "pe"
import "console"
rule Indian_APT_WinAPI{

	meta:
		Author = "Diyar Saadi"
		Date = "06/07/2024"
		Malware_Nationality = "India"
		Malware_MD5_Hash = "8C095479D9BEBA9ED56BB8D95861686D"

	condition:
		console.log("The Entry Point : ", pe.entry_point) and
		console.log("The DLL Library Details : ", pe.dll_name) 
}