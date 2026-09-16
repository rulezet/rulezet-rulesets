rule TTP_XOR_MULT_DOSStub_26e3 {
  strings:
    $key_26e3 = { 72 8b [2] 06 93 [2] 41 91 [2] 06 80 [2] 48 8c [2] 44 86 [2] 53 8d [2] 48 c3 [2] 75 }

  condition:
    any of them
}