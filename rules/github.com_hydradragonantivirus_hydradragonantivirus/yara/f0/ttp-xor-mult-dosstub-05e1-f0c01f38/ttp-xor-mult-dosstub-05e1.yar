rule TTP_XOR_MULT_DOSStub_05e1 {
  strings:
    $key_05e1 = { 51 89 [2] 25 91 [2] 62 93 [2] 25 82 [2] 6b 8e [2] 67 84 [2] 70 8f [2] 6b c1 [2] 56 }

  condition:
    any of them
}