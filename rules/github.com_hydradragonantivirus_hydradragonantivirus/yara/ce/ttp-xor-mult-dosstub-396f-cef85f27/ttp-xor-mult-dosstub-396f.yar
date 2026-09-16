rule TTP_XOR_MULT_DOSStub_396f {
  strings:
    $key_396f = { 6d 07 [2] 19 1f [2] 5e 1d [2] 19 0c [2] 57 00 [2] 5b 0a [2] 4c 01 [2] 57 4f [2] 6a }

  condition:
    any of them
}