rule TTP_XOR_MULT_DOSStub_3016 {
  strings:
    $key_3016 = { 64 7e [2] 10 66 [2] 57 64 [2] 10 75 [2] 5e 79 [2] 52 73 [2] 45 78 [2] 5e 36 [2] 63 }

  condition:
    any of them
}