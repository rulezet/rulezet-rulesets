rule CN_Toolset_sig_1433_135_sqlr {
   meta:
      description = "Detects a Chinese hacktool from a disclosed toolset - file sqlr.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://qiannao.com/ls/905300366/33834c0c/"
      date = "2015/03/30"
      score = 70
      hash = "8542c7fb8291b02db54d2dc58cd608e612bfdc57"
      id = "74038975-ef06-53d6-bdcc-02706408b596"
   strings:
      $s0 = "Connect to %s MSSQL server success. Type Command at Prompt." fullword ascii
      $s11 = ";DATABASE=master" fullword ascii
      $s12 = "xp_cmdshell '" fullword ascii
      $s14 = "SELECT * FROM OPENROWSET('SQLOLEDB','Trusted_Connection=Yes;Data Source=myserver" ascii
   condition:
      all of them
}