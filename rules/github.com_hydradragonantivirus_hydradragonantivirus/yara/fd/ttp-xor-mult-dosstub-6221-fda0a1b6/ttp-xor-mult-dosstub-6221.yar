rule TTP_XOR_MULT_DOSStub_6221 {
  strings:
    $key_6221 = { 36 49 [2] 42 51 [2] 05 53 [2] 42 42 [2] 0c 4e [2] 00 44 [2] 17 4f [2] 0c 01 [2] 31 }

  condition:
    any of them
}