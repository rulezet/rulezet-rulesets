rule TTP_XOR_MULT_DOSStub_06e1 {
  strings:
    $key_06e1 = { 52 89 [2] 26 91 [2] 61 93 [2] 26 82 [2] 68 8e [2] 64 84 [2] 73 8f [2] 68 c1 [2] 55 }

  condition:
    any of them
}