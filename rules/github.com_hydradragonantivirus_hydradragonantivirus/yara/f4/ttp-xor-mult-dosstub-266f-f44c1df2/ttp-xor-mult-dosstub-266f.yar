rule TTP_XOR_MULT_DOSStub_266f {
  strings:
    $key_266f = { 72 07 [2] 06 1f [2] 41 1d [2] 06 0c [2] 48 00 [2] 44 0a [2] 53 01 [2] 48 4f [2] 75 }

  condition:
    any of them
}