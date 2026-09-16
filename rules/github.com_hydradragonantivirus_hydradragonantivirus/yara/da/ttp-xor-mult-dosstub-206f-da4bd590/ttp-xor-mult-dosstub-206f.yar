rule TTP_XOR_MULT_DOSStub_206f {
  strings:
    $key_206f = { 74 07 [2] 00 1f [2] 47 1d [2] 00 0c [2] 4e 00 [2] 42 0a [2] 55 01 [2] 4e 4f [2] 73 }

  condition:
    any of them
}