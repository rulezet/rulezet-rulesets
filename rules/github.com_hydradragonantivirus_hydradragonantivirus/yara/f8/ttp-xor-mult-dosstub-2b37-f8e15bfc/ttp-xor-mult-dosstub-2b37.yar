rule TTP_XOR_MULT_DOSStub_2b37 {
  strings:
    $key_2b37 = { 7f 5f [2] 0b 47 [2] 4c 45 [2] 0b 54 [2] 45 58 [2] 49 52 [2] 5e 59 [2] 45 17 [2] 78 }

  condition:
    any of them
}