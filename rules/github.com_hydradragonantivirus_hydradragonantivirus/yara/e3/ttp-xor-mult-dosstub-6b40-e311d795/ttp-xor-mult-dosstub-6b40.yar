rule TTP_XOR_MULT_DOSStub_6b40 {
  strings:
    $key_6b40 = { 3f 28 [2] 4b 30 [2] 0c 32 [2] 4b 23 [2] 05 2f [2] 09 25 [2] 1e 2e [2] 05 60 [2] 38 }

  condition:
    any of them
}