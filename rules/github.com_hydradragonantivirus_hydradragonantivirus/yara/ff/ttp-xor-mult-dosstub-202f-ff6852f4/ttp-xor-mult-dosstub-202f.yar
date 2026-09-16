rule TTP_XOR_MULT_DOSStub_202f {
  strings:
    $key_202f = { 74 47 [2] 00 5f [2] 47 5d [2] 00 4c [2] 4e 40 [2] 42 4a [2] 55 41 [2] 4e 0f [2] 73 }

  condition:
    any of them
}