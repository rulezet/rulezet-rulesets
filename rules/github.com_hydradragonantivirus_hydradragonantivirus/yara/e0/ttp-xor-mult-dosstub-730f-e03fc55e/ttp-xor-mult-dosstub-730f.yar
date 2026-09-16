rule TTP_XOR_MULT_DOSStub_730f {
  strings:
    $key_730f = { 27 67 [2] 53 7f [2] 14 7d [2] 53 6c [2] 1d 60 [2] 11 6a [2] 06 61 [2] 1d 2f [2] 20 }

  condition:
    any of them
}