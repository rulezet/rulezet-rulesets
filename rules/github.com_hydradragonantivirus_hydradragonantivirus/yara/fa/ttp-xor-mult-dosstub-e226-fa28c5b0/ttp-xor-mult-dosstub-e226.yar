rule TTP_XOR_MULT_DOSStub_e226 {
  strings:
    $key_e226 = { b6 4e [2] c2 56 [2] 85 54 [2] c2 45 [2] 8c 49 [2] 80 43 [2] 97 48 [2] 8c 06 [2] b1 }

  condition:
    any of them
}