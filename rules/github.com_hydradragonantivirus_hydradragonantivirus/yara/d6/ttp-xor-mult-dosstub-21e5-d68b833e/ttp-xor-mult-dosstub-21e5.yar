rule TTP_XOR_MULT_DOSStub_21e5 {
  strings:
    $key_21e5 = { 75 8d [2] 01 95 [2] 46 97 [2] 01 86 [2] 4f 8a [2] 43 80 [2] 54 8b [2] 4f c5 [2] 72 }

  condition:
    any of them
}