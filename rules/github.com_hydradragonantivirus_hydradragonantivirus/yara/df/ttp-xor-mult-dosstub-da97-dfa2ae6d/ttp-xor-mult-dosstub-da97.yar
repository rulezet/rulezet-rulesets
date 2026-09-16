rule TTP_XOR_MULT_DOSStub_da97 {
  strings:
    $key_da97 = { 8e ff [2] fa e7 [2] bd e5 [2] fa f4 [2] b4 f8 [2] b8 f2 [2] af f9 [2] b4 b7 [2] 89 }

  condition:
    any of them
}