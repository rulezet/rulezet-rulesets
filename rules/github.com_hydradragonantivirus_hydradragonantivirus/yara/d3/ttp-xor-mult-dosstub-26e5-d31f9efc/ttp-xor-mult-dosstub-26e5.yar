rule TTP_XOR_MULT_DOSStub_26e5 {
  strings:
    $key_26e5 = { 72 8d [2] 06 95 [2] 41 97 [2] 06 86 [2] 48 8a [2] 44 80 [2] 53 8b [2] 48 c5 [2] 75 }

  condition:
    any of them
}