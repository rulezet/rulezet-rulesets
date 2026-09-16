rule HKTL_Nishang_PS1_Invoke_PowerShellTcpOneLine_RID379E : DEMO HKTL SCRIPT T1059_001 {
   meta:
      description = "Detects PowerShell Oneliner in Nishang's repository"
      author = "Florian Roth"
      reference = "https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1"
      date = "2021-03-03 17:46:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2f4c948974da341412ab742e14d8cdd33c1efa22b90135fcfae891f08494ac32"
      tags = "DEMO, HKTL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "=([text.encoding]::ASCII).GetBytes((iex $" ascii wide
      $s2 = ".GetStream();[byte[]]$" ascii wide
      $s3 = "New-Object Net.Sockets.TCPClient('" ascii wide
   condition: 
      all of them
}