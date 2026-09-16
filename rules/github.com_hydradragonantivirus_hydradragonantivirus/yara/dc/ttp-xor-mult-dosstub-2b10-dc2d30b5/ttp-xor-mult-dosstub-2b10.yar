rule TTP_XOR_MULT_DOSStub_2b10 {
  strings:
    $key_2b10 = { 7f 78 [2] 0b 60 [2] 4c 62 [2] 0b 73 [2] 45 7f [2] 49 75 [2] 5e 7e [2] 45 30 [2] 78 }

  condition:
    any of them
}