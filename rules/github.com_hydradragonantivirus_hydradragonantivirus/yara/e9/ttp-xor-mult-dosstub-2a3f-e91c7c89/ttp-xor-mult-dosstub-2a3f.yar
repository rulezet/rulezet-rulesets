rule TTP_XOR_MULT_DOSStub_2a3f {
  strings:
    $key_2a3f = { 7e 57 [2] 0a 4f [2] 4d 4d [2] 0a 5c [2] 44 50 [2] 48 5a [2] 5f 51 [2] 44 1f [2] 79 }

  condition:
    any of them
}