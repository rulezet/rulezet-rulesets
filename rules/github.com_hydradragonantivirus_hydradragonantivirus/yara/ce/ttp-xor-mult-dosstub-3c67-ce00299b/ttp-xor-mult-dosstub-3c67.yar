rule TTP_XOR_MULT_DOSStub_3c67 {
  strings:
    $key_3c67 = { 68 0f [2] 1c 17 [2] 5b 15 [2] 1c 04 [2] 52 08 [2] 5e 02 [2] 49 09 [2] 52 47 [2] 6f }

  condition:
    any of them
}