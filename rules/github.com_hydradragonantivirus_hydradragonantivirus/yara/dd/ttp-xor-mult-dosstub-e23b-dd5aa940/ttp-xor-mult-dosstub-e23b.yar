rule TTP_XOR_MULT_DOSStub_e23b {
  strings:
    $key_e23b = { b6 53 [2] c2 4b [2] 85 49 [2] c2 58 [2] 8c 54 [2] 80 5e [2] 97 55 [2] 8c 1b [2] b1 }

  condition:
    any of them
}