rule TTP_XOR_MULT_DOSStub_202d {
  strings:
    $key_202d = { 74 45 [2] 00 5d [2] 47 5f [2] 00 4e [2] 4e 42 [2] 42 48 [2] 55 43 [2] 4e 0d [2] 73 }

  condition:
    any of them
}