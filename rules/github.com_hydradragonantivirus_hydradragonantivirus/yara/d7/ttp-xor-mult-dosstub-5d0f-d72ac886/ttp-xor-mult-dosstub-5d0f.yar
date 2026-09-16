rule TTP_XOR_MULT_DOSStub_5d0f {
  strings:
    $key_5d0f = { 09 67 [2] 7d 7f [2] 3a 7d [2] 7d 6c [2] 33 60 [2] 3f 6a [2] 28 61 [2] 33 2f [2] 0e }

  condition:
    any of them
}