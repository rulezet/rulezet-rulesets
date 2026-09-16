rule ps1_toolkit_Persistence_2_RID30FF : DEMO FILE HKTL SCRIPT T1059_001 {
   meta:
      description = "Semiautomatically generated YARA rule - from files Persistence.ps1"
      author = "Florian Roth"
      reference = "https://github.com/vysec/ps1-toolkit"
      date = "2016-09-04 13:03:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e1a4dd18b481471fc25adea6a91982b7ffed1c2d393c8c17e6e542c030ac6cbd"
      tags = "DEMO, FILE, HKTL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBPAG4ASQBkAGwAZQA=')" ascii
      $s2 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBEAGEAaQBsAHkA')" ascii
      $s3 = "FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA==')" ascii
      $s4 = "[Parameter( ParameterSetName = 'ScheduledTaskAtLogon', Mandatory = $True )]" ascii
      $s5 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBBAHQATABvAGcAbwBuAA==')))" ascii
      $s6 = "[Parameter( ParameterSetName = 'PermanentWMIAtStartup', Mandatory = $True )]" fullword ascii
      $s7 = "FromBase64String('TQBlAHQAaABvAGQA')" ascii
      $s8 = "FromBase64String('VAByAGkAZwBnAGUAcgA=')" ascii
      $s9 = "[Runtime.InteropServices.CallingConvention]::Winapi," fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}