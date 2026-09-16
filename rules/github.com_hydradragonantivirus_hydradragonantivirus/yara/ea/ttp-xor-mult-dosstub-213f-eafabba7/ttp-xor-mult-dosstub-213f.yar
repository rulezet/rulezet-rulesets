rule TTP_XOR_MULT_DOSStub_213f {
  strings:
    $key_213f = { 75 57 [2] 01 4f [2] 46 4d [2] 01 5c [2] 4f 50 [2] 43 5a [2] 54 51 [2] 4f 1f [2] 72 }

  condition:
    any of them
}