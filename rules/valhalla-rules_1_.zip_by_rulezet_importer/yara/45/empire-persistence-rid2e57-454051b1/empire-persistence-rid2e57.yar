rule Empire_Persistence_RID2E57 : DEMO SCRIPT SUSP T1059_001 {
   meta:
      description = "Empire - a pure PowerShell post-exploitation agent - file Persistence.psm1"
      author = "Florian Roth"
      reference = "https://github.com/PowerShellEmpire/Empire"
      date = "2015-08-06 11:10:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, SUSP, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "C:\\PS>Add-Persistence -ScriptBlock $RickRoll -ElevatedPersistenceOption $ElevatedOptions -UserPersistenceOption $UserOptions -V" ascii
      $s2 = "# Execute the following to remove the user-level persistent payload" fullword ascii
      $s3 = "$PersistantScript = $PersistantScript.ToString().Replace('EXECUTEFUNCTION', \"$PersistenceScriptName -Persist\")" fullword ascii
   condition: 
      filesize < 108KB and 1 of them
}