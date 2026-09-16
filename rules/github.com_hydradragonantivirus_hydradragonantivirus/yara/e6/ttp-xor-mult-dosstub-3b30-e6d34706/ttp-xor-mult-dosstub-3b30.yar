rule TTP_XOR_MULT_DOSStub_3b30 {
  strings:
    $key_3b30 = { 6f 58 [2] 1b 40 [2] 5c 42 [2] 1b 53 [2] 55 5f [2] 59 55 [2] 4e 5e [2] 55 10 [2] 68 }

  condition:
    any of them
}