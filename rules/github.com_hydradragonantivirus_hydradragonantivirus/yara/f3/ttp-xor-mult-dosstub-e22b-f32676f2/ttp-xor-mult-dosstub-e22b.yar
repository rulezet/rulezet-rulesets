rule TTP_XOR_MULT_DOSStub_e22b {
  strings:
    $key_e22b = { b6 43 [2] c2 5b [2] 85 59 [2] c2 48 [2] 8c 44 [2] 80 4e [2] 97 45 [2] 8c 0b [2] b1 }

  condition:
    any of them
}