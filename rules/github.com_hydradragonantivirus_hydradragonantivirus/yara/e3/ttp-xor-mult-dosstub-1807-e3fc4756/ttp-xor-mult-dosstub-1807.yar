rule TTP_XOR_MULT_DOSStub_1807 {
  strings:
    $key_1807 = { 4c 6f [2] 38 77 [2] 7f 75 [2] 38 64 [2] 76 68 [2] 7a 62 [2] 6d 69 [2] 76 27 [2] 4b }

  condition:
    any of them
}