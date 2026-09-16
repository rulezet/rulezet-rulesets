rule TTP_XOR_MULT_DOSStub_b239 {
  strings:
    $key_b239 = { e6 51 [2] 92 49 [2] d5 4b [2] 92 5a [2] dc 56 [2] d0 5c [2] c7 57 [2] dc 19 [2] e1 }

  condition:
    any of them
}