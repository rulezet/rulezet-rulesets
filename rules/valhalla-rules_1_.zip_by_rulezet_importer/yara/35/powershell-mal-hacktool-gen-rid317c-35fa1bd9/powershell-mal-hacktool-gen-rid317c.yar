rule PowerShell_Mal_HackTool_Gen_RID317C : DEMO GEN HKTL MAL SCRIPT T1059_001 {
   meta:
      description = "Detects PowerShell hack tool samples - generic PE loader"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-11-02 13:24:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d442304ca839d75b34e30e49a8b9437b5ab60b74d85ba9005642632ce7038b32"
      tags = "DEMO, GEN, HKTL, MAL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "$PEBytes32 = 'TVqQAAMAAAAEAAAA" wide
      $x2 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp" fullword wide
      $x3 = "@($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword wide
      $x4 = "(Shellcode: LoadLibraryA.asm)" fullword wide
   condition: 
      filesize < 8000KB and 1 of them
}