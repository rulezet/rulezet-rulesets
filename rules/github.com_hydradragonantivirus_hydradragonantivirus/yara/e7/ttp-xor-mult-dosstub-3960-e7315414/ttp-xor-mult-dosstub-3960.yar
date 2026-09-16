rule TTP_XOR_MULT_DOSStub_3960 {
  strings:
    $key_3960 = { 6d 08 [2] 19 10 [2] 5e 12 [2] 19 03 [2] 57 0f [2] 5b 05 [2] 4c 0e [2] 57 40 [2] 6a }

  condition:
    any of them
}