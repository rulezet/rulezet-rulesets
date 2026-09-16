rule TTP_XOR_MULT_DOSStub_110a {
  strings:
    $key_110a = { 45 62 [2] 31 7a [2] 76 78 [2] 31 69 [2] 7f 65 [2] 73 6f [2] 64 64 [2] 7f 2a [2] 42 }

  condition:
    any of them
}