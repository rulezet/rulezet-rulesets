import "pe"
rule __PseudoSigner_0_1_rule__ASProtect______Anorganix {
  strings:
    $a0 = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9 }

  condition:
    $a0 at pe.entry_point
}