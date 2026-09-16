rule TTP_XOR_MULT_DOSStub_3010 {
  strings:
    $key_3010 = { 64 78 [2] 10 60 [2] 57 62 [2] 10 73 [2] 5e 7f [2] 52 75 [2] 45 7e [2] 5e 30 [2] 63 }

  condition:
    any of them
}