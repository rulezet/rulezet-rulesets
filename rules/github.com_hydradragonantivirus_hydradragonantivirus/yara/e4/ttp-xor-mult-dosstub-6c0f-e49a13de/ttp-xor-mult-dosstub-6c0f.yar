rule TTP_XOR_MULT_DOSStub_6c0f {
  strings:
    $key_6c0f = { 38 67 [2] 4c 7f [2] 0b 7d [2] 4c 6c [2] 02 60 [2] 0e 6a [2] 19 61 [2] 02 2f [2] 3f }

  condition:
    any of them
}