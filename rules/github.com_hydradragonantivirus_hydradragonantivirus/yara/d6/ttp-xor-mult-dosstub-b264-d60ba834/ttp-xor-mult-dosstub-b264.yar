rule TTP_XOR_MULT_DOSStub_b264 {
  strings:
    $key_b264 = { e6 0c [2] 92 14 [2] d5 16 [2] 92 07 [2] dc 0b [2] d0 01 [2] c7 0a [2] dc 44 [2] e1 }

  condition:
    any of them
}