rule TTP_XOR_MULT_DOSStub_2be5 {
  strings:
    $key_2be5 = { 7f 8d [2] 0b 95 [2] 4c 97 [2] 0b 86 [2] 45 8a [2] 49 80 [2] 5e 8b [2] 45 c5 [2] 78 }

  condition:
    any of them
}