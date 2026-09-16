rule TTP_XOR_MULT_DOSStub_5b67 {
  strings:
    $key_5b67 = { 0f 0f [2] 7b 17 [2] 3c 15 [2] 7b 04 [2] 35 08 [2] 39 02 [2] 2e 09 [2] 35 47 [2] 08 }

  condition:
    any of them
}