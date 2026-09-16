rule TTP_XOR_MULT_DOSStub_2b5a {
  strings:
    $key_2b5a = { 7f 32 [2] 0b 2a [2] 4c 28 [2] 0b 39 [2] 45 35 [2] 49 3f [2] 5e 34 [2] 45 7a [2] 78 }

  condition:
    any of them
}