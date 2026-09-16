rule MAL_QBot_HTML_Smuggling_Indicators_Oct22_1_RID3648 : DEMO MAL Qakbot {
   meta:
      description = "Detects double encoded PKZIP headers as seen in HTML files used by QBot"
      author = "Florian Roth"
      reference = "https://twitter.com/ankit_anubhav/status/1578257383133876225?s=20&t=Bu3CCJCzImpTGOQX_KGsdA"
      date = "2022-10-07 16:49:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4f384bcba31fda53e504d0a6c85cee0ce3ea9586226633d063f34c53ddeaca3f"
      hash2 = "8e61c2b751682becb4c0337f5a79b2da0f5f19c128b162ec8058104b894cae9b"
      hash3 = "c5d23d991ce3fbcf73b177bc6136d26a501ded318ccf409ca16f7c664727755a"
      tags = "DEMO, MAL, Qakbot"
      minimum_yara = "3.5.0"
      
   strings:
      $sd1 = "VUVzREJCUUFBUUFJQ" 
      $sd2 = "VFc0RCQlFBQVFBSU" 
      $sd3 = "VRXNEQkJRQUFRQUlB" 
      $sdr1 = "QJFUUBFUUCJERzVUV" 
      $sdr2 = "USBFVQBFlQCR0cFV" 
      $sdr3 = "BlUQRFUQRJkQENXRV" 
      $st1 = "VlVWelJFSkNVVUZCVVVGSl" 
      $st2 = "ZVVnpSRUpDVVVGQlVVRkpR" 
      $st3 = "WVVZ6UkVKQ1VVRkJVVUZKU" 
      $st4 = "VkZjMFJDUWxGQlFWRkJTV" 
      $st5 = "ZGYzBSQ1FsRkJRVkZCU1" 
      $st6 = "WRmMwUkNRbEZCUVZGQlNV" 
      $st7 = "VlJYTkVRa0pSUVVGUlFVbE" 
      $st8 = "ZSWE5FUWtKUlFVRlJRVWxC" 
      $st9 = "WUlhORVFrSlJRVUZSUVVsQ" 
      $str1 = "UUpGVVVCRlVVQ0pFUnpWVV" 
      $str2 = "FKRlVVQkZVVUNKRVJ6VlVW" 
      $str3 = "RSkZVVUJGVVVDSkVSelZVV" 
      $str4 = "VVNCRlZRQkZsUUNSMGNGV" 
      $str5 = "VTQkZWUUJGbFFDUjBjRl" 
      $str6 = "VU0JGVlFCRmxRQ1IwY0ZW" 
      $str7 = "QmxVUVJGVVFSSmtRRU5YUl" 
      $str8 = "JsVVFSRlVRUkprUUVOWFJW" 
      $str9 = "CbFVRUkZVUVJKa1FFTlhSV" 
      $htm = "<html" ascii
      $eml = "Content-Transfer-Encoding:" ascii
   condition: 
      filesize < 10MB and ( ( 1 of ( $sd* ) and $htm and not $eml ) or ( 1 of ( $st* ) and $eml ) )
}