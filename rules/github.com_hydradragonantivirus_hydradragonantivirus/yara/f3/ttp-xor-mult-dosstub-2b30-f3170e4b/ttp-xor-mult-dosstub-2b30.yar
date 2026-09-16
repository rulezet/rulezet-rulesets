rule TTP_XOR_MULT_DOSStub_2b30 {
  strings:
    $key_2b30 = { 7f 58 [2] 0b 40 [2] 4c 42 [2] 0b 53 [2] 45 5f [2] 49 55 [2] 5e 5e [2] 45 10 [2] 78 }

  condition:
    any of them
}