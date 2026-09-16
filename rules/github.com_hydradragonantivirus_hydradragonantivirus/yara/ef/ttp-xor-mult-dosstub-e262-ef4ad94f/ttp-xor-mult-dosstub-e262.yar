rule TTP_XOR_MULT_DOSStub_e262 {
  strings:
    $key_e262 = { b6 0a [2] c2 12 [2] 85 10 [2] c2 01 [2] 8c 0d [2] 80 07 [2] 97 0c [2] 8c 42 [2] b1 }

  condition:
    any of them
}