rule TTP_XOR_MULT_DOSStub_7d10 {
  strings:
    $key_7d10 = { 29 78 [2] 5d 60 [2] 1a 62 [2] 5d 73 [2] 13 7f [2] 1f 75 [2] 08 7e [2] 13 30 [2] 2e }

  condition:
    any of them
}