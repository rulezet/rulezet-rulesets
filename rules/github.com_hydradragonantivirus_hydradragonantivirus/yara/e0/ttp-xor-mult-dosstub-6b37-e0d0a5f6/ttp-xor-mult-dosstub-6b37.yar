rule TTP_XOR_MULT_DOSStub_6b37 {
  strings:
    $key_6b37 = { 3f 5f [2] 4b 47 [2] 0c 45 [2] 4b 54 [2] 05 58 [2] 09 52 [2] 1e 59 [2] 05 17 [2] 38 }

  condition:
    any of them
}