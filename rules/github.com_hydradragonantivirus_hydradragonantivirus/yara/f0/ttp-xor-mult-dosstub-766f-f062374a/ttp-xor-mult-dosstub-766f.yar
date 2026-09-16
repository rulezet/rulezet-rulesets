rule TTP_XOR_MULT_DOSStub_766f {
  strings:
    $key_766f = { 22 07 [2] 56 1f [2] 11 1d [2] 56 0c [2] 18 00 [2] 14 0a [2] 03 01 [2] 18 4f [2] 25 }

  condition:
    any of them
}