rule TTP_XOR_MULT_DOSStub_00e1 {
  strings:
    $key_00e1 = { 54 89 [2] 20 91 [2] 67 93 [2] 20 82 [2] 6e 8e [2] 62 84 [2] 75 8f [2] 6e c1 [2] 53 }

  condition:
    any of them
}