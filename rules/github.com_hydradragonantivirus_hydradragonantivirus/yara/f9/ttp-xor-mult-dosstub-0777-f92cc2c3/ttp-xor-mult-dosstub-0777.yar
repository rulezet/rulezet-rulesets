rule TTP_XOR_MULT_DOSStub_0777 {
  strings:
    $key_0777 = { 53 1f [2] 27 07 [2] 60 05 [2] 27 14 [2] 69 18 [2] 65 12 [2] 72 19 [2] 69 57 [2] 54 }

  condition:
    any of them
}