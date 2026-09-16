rule TTP_XOR_MULT_DOSStub_736f {
  strings:
    $key_736f = { 27 07 [2] 53 1f [2] 14 1d [2] 53 0c [2] 1d 00 [2] 11 0a [2] 06 01 [2] 1d 4f [2] 20 }

  condition:
    any of them
}