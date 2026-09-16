rule TTP_XOR_MULT_DOSStub_6c67 {
  strings:
    $key_6c67 = { 38 0f [2] 4c 17 [2] 0b 15 [2] 4c 04 [2] 02 08 [2] 0e 02 [2] 19 09 [2] 02 47 [2] 3f }

  condition:
    any of them
}