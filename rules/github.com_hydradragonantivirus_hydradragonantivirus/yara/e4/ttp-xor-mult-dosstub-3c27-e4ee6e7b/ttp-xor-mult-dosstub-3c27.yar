rule TTP_XOR_MULT_DOSStub_3c27 {
  strings:
    $key_3c27 = { 68 4f [2] 1c 57 [2] 5b 55 [2] 1c 44 [2] 52 48 [2] 5e 42 [2] 49 49 [2] 52 07 [2] 6f }

  condition:
    any of them
}