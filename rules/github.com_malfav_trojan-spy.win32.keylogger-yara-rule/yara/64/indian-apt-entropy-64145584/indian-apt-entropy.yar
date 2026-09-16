import "math"
rule Indian_APT_Entropy{

	meta:
		Author = "Diyar Saadi"
		Date = "06/07/2024"
		Malware_Nationality = "India"
		Malware_MD5_Hash = "8C095479D9BEBA9ED56BB8D95861686D"

	condition:
		math.entropy(0, filesize) > 7.5 
}