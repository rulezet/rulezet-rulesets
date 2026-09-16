rule TTP_XOR_MULT_DOSStub_113a {
  strings:
    $key_113a = { 45 52 [2] 31 4a [2] 76 48 [2] 31 59 [2] 7f 55 [2] 73 5f [2] 64 54 [2] 7f 1a [2] 42 }

  condition:
    any of them
}