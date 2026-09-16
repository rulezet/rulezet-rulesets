rule PEiD_03500_XCF_File_Format_by_Adeline_Software_ {
  meta:
    description = "[XCF File Format by Adeline Software]"
    ep_only     = "false"

  strings:
    $a = { 46 72 61 6D 65 4C 65 6E F4 0F }

  condition:
    $a
}