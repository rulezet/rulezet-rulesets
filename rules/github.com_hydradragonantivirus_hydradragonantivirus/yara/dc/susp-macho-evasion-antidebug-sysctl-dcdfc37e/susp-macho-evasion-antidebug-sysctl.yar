rule SUSP_Macho_Evasion_AntiDebug_sysctl {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-02-02"
    version     = "1.0"
    description = "check Macho files for likely anti-debugging related strings like sysctl"
    reference   = "https://www.crowdstrike.com/blog/how-crowdstrike-analyzes-macos-malware-to-optimize-automated-detection-capabilities/"

  strings:
    $ = "sysctl" nocase ascii wide

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    all of them
}