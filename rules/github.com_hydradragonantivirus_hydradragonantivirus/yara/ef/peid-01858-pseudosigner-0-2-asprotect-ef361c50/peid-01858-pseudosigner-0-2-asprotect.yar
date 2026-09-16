rule PEiD_01858_PseudoSigner_0_2__ASProtect__ {
  meta:
    description = "[PseudoSigner 0.2 [ASProtect]]"
    ep_only     = "true"

  strings:
    $a = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD }

  condition:
    $a
}