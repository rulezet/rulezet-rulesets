rule TeleBots_CredRaptor_Password_Stealer_RID3569 : APT DEMO EXE FILE G0034 T1003 credraptor {
   meta:
      description = "Detects TeleBots malware - CredRaptor Password Stealer"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/"
      date = "2016-12-14 16:12:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "50b990f6555055a265fde98324759dbc74619d6a7c49b9fd786775299bf77d26"
      tags = "APT, DEMO, EXE, FILE, G0034, T1003, credraptor"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "C:\\Documents and Settings\\Administrator\\Desktop\\GetPAI\\Out\\IE.pdb" fullword ascii
      $s2 = "SELECT encryptedUsername, encryptedPassword, hostname,httpRealm FROM moz_logins" fullword ascii
      $s3 = "SELECT ORIGIN_URL,USERNAME_VALUE,PASSWORD_VALUE FROM LOGINS" fullword ascii
      $s4 = ".\\PAI\\IEforXPpasswords.txt" ascii
      $s5 = "\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii
      $s6 = "Opera old version credentials" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 2 of them ) or ( 4 of them )
}