rule TTP_XOR_MULT_DOSStub_e21b {
  strings:
    $key_e21b = { b6 73 [2] c2 6b [2] 85 69 [2] c2 78 [2] 8c 74 [2] 80 7e [2] 97 75 [2] 8c 3b [2] b1 }

  condition:
    any of them
}