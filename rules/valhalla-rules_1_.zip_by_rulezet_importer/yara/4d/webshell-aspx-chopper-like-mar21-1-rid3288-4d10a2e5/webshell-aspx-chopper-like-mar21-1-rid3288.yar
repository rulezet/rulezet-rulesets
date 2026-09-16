rule WEBSHELL_ASPX_Chopper_Like_Mar21_1_RID3288 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Chopper like ASPX Webshells"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2021-03-31 14:09:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ac44513e5ef93d8cbc17219350682c2246af6d5eb85c1b4302141d94c3b06c90"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "http://f/<script language=\"JScript\" runat=\"server\">var _0x" ascii
      $s2 = "));function Page_Load(){var _0x" ascii
      $s3 = ";eval(Request[_0x" ascii
      $s4 = "','orange','unsafe','" ascii
   condition: 
      filesize < 3KB and 1 of them or 2 of them
}