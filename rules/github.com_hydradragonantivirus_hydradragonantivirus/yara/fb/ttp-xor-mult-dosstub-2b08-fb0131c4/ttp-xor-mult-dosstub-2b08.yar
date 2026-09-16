rule TTP_XOR_MULT_DOSStub_2b08 {
  strings:
    $key_2b08 = { 7f 60 [2] 0b 78 [2] 4c 7a [2] 0b 6b [2] 45 67 [2] 49 6d [2] 5e 66 [2] 45 28 [2] 78 }

  condition:
    any of them
}