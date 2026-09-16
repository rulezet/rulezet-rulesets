rule TTP_XOR_MULT_DOSStub_2157 {
  strings:
    $key_2157 = { 75 3f [2] 01 27 [2] 46 25 [2] 01 34 [2] 4f 38 [2] 43 32 [2] 54 39 [2] 4f 77 [2] 72 }

  condition:
    any of them
}