rule TTP_XOR_MULT_DOSStub_26f8 {
  strings:
    $key_26f8 = { 72 90 [2] 06 88 [2] 41 8a [2] 06 9b [2] 48 97 [2] 44 9d [2] 53 96 [2] 48 d8 [2] 75 }

  condition:
    any of them
}