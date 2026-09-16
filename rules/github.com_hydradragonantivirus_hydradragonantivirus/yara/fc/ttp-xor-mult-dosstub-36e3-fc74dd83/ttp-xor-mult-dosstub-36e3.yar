rule TTP_XOR_MULT_DOSStub_36e3 {
  strings:
    $key_36e3 = { 62 8b [2] 16 93 [2] 51 91 [2] 16 80 [2] 58 8c [2] 54 86 [2] 43 8d [2] 58 c3 [2] 65 }

  condition:
    any of them
}