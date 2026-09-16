rule ItsSoEasy_Ransomware_C_Var {
    meta:
		description = "Detect ItsSoEasy Ransomware (Itssoeasy-A C.Var)"
		author = "bstnbuck"
		date = "2023-11-02"
        yarahub_author_twitter = "@bstnbuck"
        yarahub_reference_link = "https://github.com/bstnbuck/ItsSoEasy"
        yarahub_uuid = "ad8b93fa-22bc-4c2a-b15f-35462f85d944"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "1ce280542553dc383b768b9189808e27"
    
	strings:
		$typ1 = "itssoeasy" nocase
		$typ1_wide = "itssoeasy" nocase wide
		$typ2 = "itssoeasy" base64
		$typ3 = "ItsSoEasy" base64

						$c2m1 = "d2VsbCB0aGlzIHN1Y2tzLCBoYSE="  
				$c2m2 = "aGFzIHRoaXMgaWRpb3QgcGF5ZWQgdGhlIHJhbnNvbT8="
				$c2m3 = "b2gsIHlvdSdyZSBnb29kIQ=="          
				$c2m4 = "bW9uZXksIG1vbmV5LCBtb25leSE="        
				$c2m5 = "aSBuZWVkIHRoaXMgdG8gZnVjayB5b3UgdXAh"   
				$c2m6 = "LS1LRVktUFJPQ0VEVVJFLS0="                     
		
						$tkmsgMsg = "RGVjcnlwdCBmaWxlcyBub3c/"
				$tkmsg1Msg = "V2hvb3BzIHlvdXIgcGVyc29uYWwgZGF0YSB3YXMgZW5jcnlwdGVkISBSZWFkIHRoZSBpbmRleC5odG1sIG9uIHRoZSBEZXNrdG9wIGhvdyB0byBkZWNyeXB0IGl0"
				$tkmsg2Msg = "Tm93IHlvdXIgZGF0YSBpcyBsb3N0" 
				$tkmsg3Msg = "SXQgd2FzIGFzIGVhc3kgYXMgSSBzYWlkLCBoYT8=" 

				$fileFiles = "L2lmX3lvdV9jaGFuZ2VfdGhpc19maWxlX3lvdXJfZGF0YV9pc19sb3N0" 				$fileident = "L2lkZW50aWZpZXI=" 
				$filetype = "Lml0c3NvZWFzeQ==" 
		$fileransom = "itssoeasy.html"

				$cmd1 = "Welcome to the Google connector!\nPlease wait while the installer runs..."
		$cmd2 = "Do not destroy the current process, otherwise your data will be irreversibly encrypted."
		$cmd3 = "Please use the instructions in the .html file on your Desktop or your Home-Directory to decrypt your data"
		$cmd4 = "If you payed, this window will automatically check and decrypt your data."
		$cmd5 = "Wow! You're good. Now i will recover your files!\n => Do not kill this process, otherwise your data is lost!"
		$cmd6 = "Your files has been decrypted!\nThank you and Goodbye."

    condition:
        any of ($typ*) and all of ($c2*, $tkmsg*, $file*, $cmd*) and (filesize < 100KB or (filesize > 1MB and filesize < 3MB))
}