rule TTP_XOR_MULT_DOSStub_21e7 {
  strings:
    $key_21e7 = { 75 8f [2] 01 97 [2] 46 95 [2] 01 84 [2] 4f 88 [2] 43 82 [2] 54 89 [2] 4f c7 [2] 72 }

  condition:
    any of them
}