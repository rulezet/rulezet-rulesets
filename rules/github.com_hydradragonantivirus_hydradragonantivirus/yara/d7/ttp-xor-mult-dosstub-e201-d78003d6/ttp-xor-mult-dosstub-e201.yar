rule TTP_XOR_MULT_DOSStub_e201 {
  strings:
    $key_e201 = { b6 69 [2] c2 71 [2] 85 73 [2] c2 62 [2] 8c 6e [2] 80 64 [2] 97 6f [2] 8c 21 [2] b1 }

  condition:
    any of them
}