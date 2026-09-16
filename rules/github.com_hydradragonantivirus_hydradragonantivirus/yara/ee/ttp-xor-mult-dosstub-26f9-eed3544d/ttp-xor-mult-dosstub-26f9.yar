rule TTP_XOR_MULT_DOSStub_26f9 {
  strings:
    $key_26f9 = { 72 91 [2] 06 89 [2] 41 8b [2] 06 9a [2] 48 96 [2] 44 9c [2] 53 97 [2] 48 d9 [2] 75 }

  condition:
    any of them
}