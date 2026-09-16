rule TTP_XOR_MULT_DOSStub_2b15 {
  strings:
    $key_2b15 = { 7f 7d [2] 0b 65 [2] 4c 67 [2] 0b 76 [2] 45 7a [2] 49 70 [2] 5e 7b [2] 45 35 [2] 78 }

  condition:
    any of them
}