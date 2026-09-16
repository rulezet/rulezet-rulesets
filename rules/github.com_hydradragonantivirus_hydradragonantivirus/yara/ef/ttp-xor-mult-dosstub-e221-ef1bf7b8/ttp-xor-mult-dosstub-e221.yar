rule TTP_XOR_MULT_DOSStub_e221 {
  strings:
    $key_e221 = { b6 49 [2] c2 51 [2] 85 53 [2] c2 42 [2] 8c 4e [2] 80 44 [2] 97 4f [2] 8c 01 [2] b1 }

  condition:
    any of them
}