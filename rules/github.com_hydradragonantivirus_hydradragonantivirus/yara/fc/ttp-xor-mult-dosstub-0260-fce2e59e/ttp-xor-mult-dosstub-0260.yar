rule TTP_XOR_MULT_DOSStub_0260 {
  strings:
    $key_0260 = { 56 08 [2] 22 10 [2] 65 12 [2] 22 03 [2] 6c 0f [2] 60 05 [2] 77 0e [2] 6c 40 [2] 51 }

  condition:
    any of them
}