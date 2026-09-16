rule TTP_XOR_MULT_DOSStub_2936 {
  strings:
    $key_2936 = { 7d 5e [2] 09 46 [2] 4e 44 [2] 09 55 [2] 47 59 [2] 4b 53 [2] 5c 58 [2] 47 16 [2] 7a }

  condition:
    any of them
}