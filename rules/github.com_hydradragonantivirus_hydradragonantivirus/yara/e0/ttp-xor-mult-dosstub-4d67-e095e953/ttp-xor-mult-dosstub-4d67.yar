rule TTP_XOR_MULT_DOSStub_4d67 {
  strings:
    $key_4d67 = { 19 0f [2] 6d 17 [2] 2a 15 [2] 6d 04 [2] 23 08 [2] 2f 02 [2] 38 09 [2] 23 47 [2] 1e }

  condition:
    any of them
}