rule TTP_XOR_MULT_DOSStub_b275 {
  strings:
    $key_b275 = { e6 1d [2] 92 05 [2] d5 07 [2] 92 16 [2] dc 1a [2] d0 10 [2] c7 1b [2] dc 55 [2] e1 }

  condition:
    any of them
}