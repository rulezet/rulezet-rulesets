rule TTP_XOR_MULT_DOSStub_442f {
  strings:
    $key_442f = { 10 47 [2] 64 5f [2] 23 5d [2] 64 4c [2] 2a 40 [2] 26 4a [2] 31 41 [2] 2a 0f [2] 17 }

  condition:
    any of them
}