rule TTP_XOR_MULT_DOSStub_333f {
  strings:
    $key_333f = { 67 57 [2] 13 4f [2] 54 4d [2] 13 5c [2] 5d 50 [2] 51 5a [2] 46 51 [2] 5d 1f [2] 60 }

  condition:
    any of them
}