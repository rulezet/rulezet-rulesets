rule TTP_XOR_MULT_DOSStub_331f {
  strings:
    $key_331f = { 67 77 [2] 13 6f [2] 54 6d [2] 13 7c [2] 5d 70 [2] 51 7a [2] 46 71 [2] 5d 3f [2] 60 }

  condition:
    any of them
}