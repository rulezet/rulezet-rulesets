rule TTP_XOR_MULT_DOSStub_316f {
  strings:
    $key_316f = { 65 07 [2] 11 1f [2] 56 1d [2] 11 0c [2] 5f 00 [2] 53 0a [2] 44 01 [2] 5f 4f [2] 62 }

  condition:
    any of them
}