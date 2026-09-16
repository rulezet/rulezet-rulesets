rule TTP_XOR_MULT_DOSStub_b229 {
  strings:
    $key_b229 = { e6 41 [2] 92 59 [2] d5 5b [2] 92 4a [2] dc 46 [2] d0 4c [2] c7 47 [2] dc 09 [2] e1 }

  condition:
    any of them
}