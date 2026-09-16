rule TTP_XOR_MULT_DOSStub_752f {
  strings:
    $key_752f = { 21 47 [2] 55 5f [2] 12 5d [2] 55 4c [2] 1b 40 [2] 17 4a [2] 00 41 [2] 1b 0f [2] 26 }

  condition:
    any of them
}