rule TTP_XOR_MULT_DOSStub_e207 {
  strings:
    $key_e207 = { b6 6f [2] c2 77 [2] 85 75 [2] c2 64 [2] 8c 68 [2] 80 62 [2] 97 69 [2] 8c 27 [2] b1 }

  condition:
    any of them
}