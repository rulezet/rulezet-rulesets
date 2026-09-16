rule nskbfltr {
  meta:
    description = "19438 - file nskbfltr.inf"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
    date        = "2023-10-29"
    hash1       = "d96856cd944a9f1587907cacef974c0248b7f4210f1689c1e6bcac5fed289368"

  strings:
    $s1 = ";--- nskbfltr Coinstaller installation ------" fullword ascii
    $s2 = "; This inf file installs the WDF Framework binaries" fullword ascii
    $s3 = "KmdfService = nskbfltr, nskbfltr_wdfsect" fullword ascii
    $s4 = "KmdfLibraryVersion = 1.5" fullword ascii
    $s5 = "; NS Keyboard Filter" fullword ascii
    $s6 = "; nskbfltr.inf" fullword ascii
    $s7 = "[nskbfltr.NT.Wdf]" fullword ascii
    $s8 = "[nskbfltr_wdfsect]" fullword ascii
    $s9 = "Provider=NSL" fullword ascii

  condition:
    uint16(0) == 0x203b and filesize < 1KB and
    all of them
}