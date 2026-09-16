rule TTP_XOR_MULT_DOSStub_c982 {
  strings:
    $key_c982 = { 9d ea [2] e9 f2 [2] ae f0 [2] e9 e1 [2] a7 ed [2] ab e7 [2] bc ec [2] a7 a2 [2] 9a }

  condition:
    any of them
}