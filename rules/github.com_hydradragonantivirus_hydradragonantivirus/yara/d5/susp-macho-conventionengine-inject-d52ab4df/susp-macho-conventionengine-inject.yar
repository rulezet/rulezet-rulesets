rule SUSP_Macho_ConventionEngine_Inject {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-31"
    version     = "1.0"
    description = "using ConventionEngine Style Rules Checking for Macho Files that share some potential functionality via the string Inject"

  strings:
    $ = "Inject" nocase ascii wide

  condition:
    (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE)
    and all of them
}