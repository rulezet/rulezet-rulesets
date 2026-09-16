rule WiltedTulip_powershell_RID302C : APT DEMO SCRIPT T1059_001 {
   meta:
      description = "Detects powershell script used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23 12:28:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e5ee1f45cbfdb54b02180e158c3c1f080d89bce6a7d1fe99dd0ff09d47a36787"
      tags = "APT, DEMO, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "powershell.exe -nop -w hidden -c if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+" ascii
   condition: 
      1 of them
}