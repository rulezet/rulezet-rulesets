rule PEiD_01848_PseudoSigner_0_1__VBOX_4_3_MTE_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [VBOX 4.3 MTE] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 E9 }

  condition:
    $a
}