rule TTP_XOR_MULT_DOSStub_3710 {
  strings:
    $key_3710 = { 63 78 [2] 17 60 [2] 50 62 [2] 17 73 [2] 59 7f [2] 55 75 [2] 42 7e [2] 59 30 [2] 64 }

  condition:
    any of them
}