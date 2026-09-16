rule TTP_XOR_MULT_DOSStub_6b27 {
  strings:
    $key_6b27 = { 3f 4f [2] 4b 57 [2] 0c 55 [2] 4b 44 [2] 05 48 [2] 09 42 [2] 1e 49 [2] 05 07 [2] 38 }

  condition:
    any of them
}