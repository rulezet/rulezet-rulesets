rule APT_MAL_ASPX_HAFNIUM_Chopper_Mar21_4_RID32D6 : APT DEMO G0125 MAL T1505_003 {
   meta:
      description = "Detects HAFNIUM ASPX files dropped on compromised servers"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
      date = "2021-03-07 14:22:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, G0125, MAL, T1505_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<%@Page Language=\"Jscript\"%>" ascii wide nocase
      $s2 = ".FromBase64String(" ascii wide nocase
      $s3 = "eval(System.Text.Encoding." ascii wide nocase
   condition: 
      filesize < 850 and all of them
}