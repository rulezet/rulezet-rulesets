rule TTP_XOR_MULT_DOSStub_347f {
  strings:
    $key_347f = { 60 17 [2] 14 0f [2] 53 0d [2] 14 1c [2] 5a 10 [2] 56 1a [2] 41 11 [2] 5a 5f [2] 67 }

  condition:
    any of them
}