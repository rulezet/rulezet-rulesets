rule TTP_XOR_MULT_DOSStub_6b77 {
  strings:
    $key_6b77 = { 3f 1f [2] 4b 07 [2] 0c 05 [2] 4b 14 [2] 05 18 [2] 09 12 [2] 1e 19 [2] 05 57 [2] 38 }

  condition:
    any of them
}