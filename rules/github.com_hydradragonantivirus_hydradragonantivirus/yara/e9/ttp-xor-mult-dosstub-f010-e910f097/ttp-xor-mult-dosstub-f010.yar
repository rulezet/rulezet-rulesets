rule TTP_XOR_MULT_DOSStub_f010 {
  strings:
    $key_f010 = { a4 78 [2] d0 60 [2] 97 62 [2] d0 73 [2] 9e 7f [2] 92 75 [2] 85 7e [2] 9e 30 [2] a3 }

  condition:
    any of them
}