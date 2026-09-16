rule APT_APT29_NOBELIUM_LNK_Samples_May21_1_RID3350 : APT DEMO FILE G0016 G0118 RUSSIA T1210 T1218_011 T1547_009 {
   meta:
      description = "Detects link file characteristics as described in APT29 NOBELIUM report"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
      date = "2021-05-27 14:42:31"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "24caf54e7c3fe308444093f7ac64d6d520c8f44ea4251e09e24931bdb72f5548"
      tags = "APT, DEMO, FILE, G0016, G0118, RUSSIA, T1210, T1218_011, T1547_009"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "rundll32.exe" wide
      $sa1 = "IMGMountingService.dll" wide
      $sa2 = "MountImgHelper" wide
      $sb1 = "diassvcs.dll" wide
      $sb2 = "InitializeComponent" wide
      $sc1 = "MsDiskMountService.dll" wide
      $sc2 = "DiskDriveIni" wide
      $sd1 = "GraphicalComponent.dll" wide
      $sd2 = "VisualServiceComponent" wide
      $se1 = "data/mstu.dll,MicrosoftUpdateService" wide
   condition: 
      uint16 ( 0 ) == 0x004c and filesize < 4KB and $a1 and ( all of ( $sa* ) or all of ( $sb* ) or all of ( $sc* ) or all of ( $sd* ) or all of ( $se* ) )
}