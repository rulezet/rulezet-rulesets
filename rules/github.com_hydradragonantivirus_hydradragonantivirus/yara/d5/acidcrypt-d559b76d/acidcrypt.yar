rule acidcrypt {
  meta:
    author      = "PEiD"
    description = "AcidCrypt -> AciDLeo"
    group       = "102"
    function    = "0"

  strings:
    $a0 = { BE ?? ?? ?? ?? 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }

  condition:
    $a0
}