rule TTP_XOR_MULT_DOSStub_e2ec {
  strings:
    $key_e2ec = { b6 84 [2] c2 9c [2] 85 9e [2] c2 8f [2] 8c 83 [2] 80 89 [2] 97 82 [2] 8c cc [2] b1 }

  condition:
    any of them
}