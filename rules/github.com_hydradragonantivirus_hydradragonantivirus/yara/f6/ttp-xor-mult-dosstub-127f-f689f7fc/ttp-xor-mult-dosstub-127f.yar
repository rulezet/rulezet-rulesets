rule TTP_XOR_MULT_DOSStub_127f {
  strings:
    $key_127f = { 46 17 [2] 32 0f [2] 75 0d [2] 32 1c [2] 7c 10 [2] 70 1a [2] 67 11 [2] 7c 5f [2] 41 }

  condition:
    any of them
}