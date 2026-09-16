rule APT_NK_TradingTech_ForensicArtifacts_Apr23_1_RID374A : APT DEMO FILE G1049 NK {
   meta:
      description = "Detects forensic artifacts, file names and keywords related the Trading Technologies compromise UNC4736"
      author = "Florian Roth"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20 17:32:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-04-21"
      tags = "APT, DEMO, FILE, G1049, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "www.tradingtechnologies.com/trading/order-management" ascii wide
      $xf1 = "X_TRADER_r7.17.90p608.exe" ascii wide
      $xf2 = "\\X_TRADER-ja.mst" ascii wide
      $xf3 = "C:\\Programdata\\TPM\\TpmVscMgrSvr.exe" ascii wide
      $xf4 = "C:\\Programdata\\TPM\\winscard.dll" ascii wide
      $fp1 = "<html" 
   condition: 
      not uint16 ( 0 ) == 0x5025 and 1 of ( $x* ) and not 1 of ( $fp* )
}