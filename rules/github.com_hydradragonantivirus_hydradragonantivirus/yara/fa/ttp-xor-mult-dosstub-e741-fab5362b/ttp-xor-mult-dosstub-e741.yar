rule TTP_XOR_MULT_DOSStub_e741 {
  strings:
    $key_e741 = { b3 29 [2] c7 31 [2] 80 33 [2] c7 22 [2] 89 2e [2] 85 24 [2] 92 2f [2] 89 61 [2] b4 }

  condition:
    any of them
}