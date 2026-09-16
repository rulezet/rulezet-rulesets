rule TTP_XOR_MULT_DOSStub_7c60 {
  strings:
    $key_7c60 = { 28 08 [2] 5c 10 [2] 1b 12 [2] 5c 03 [2] 12 0f [2] 1e 05 [2] 09 0e [2] 12 40 [2] 2f }

  condition:
    any of them
}