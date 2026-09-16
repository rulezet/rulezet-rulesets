rule TTP_XOR_MULT_DOSStub_6b6f {
  strings:
    $key_6b6f = { 3f 07 [2] 4b 1f [2] 0c 1d [2] 4b 0c [2] 05 00 [2] 09 0a [2] 1e 01 [2] 05 4f [2] 38 }

  condition:
    any of them
}