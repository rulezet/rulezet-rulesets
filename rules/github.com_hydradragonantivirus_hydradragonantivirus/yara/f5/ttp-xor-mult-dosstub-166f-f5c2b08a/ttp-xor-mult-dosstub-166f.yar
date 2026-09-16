rule TTP_XOR_MULT_DOSStub_166f {
  strings:
    $key_166f = { 42 07 [2] 36 1f [2] 71 1d [2] 36 0c [2] 78 00 [2] 74 0a [2] 63 01 [2] 78 4f [2] 45 }

  condition:
    any of them
}