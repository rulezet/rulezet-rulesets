rule TTP_XOR_MULT_DOSStub_2b31 {
  strings:
    $key_2b31 = { 7f 59 [2] 0b 41 [2] 4c 43 [2] 0b 52 [2] 45 5e [2] 49 54 [2] 5e 5f [2] 45 11 [2] 78 }

  condition:
    any of them
}