rule TTP_XOR_MULT_DOSStub_5d2f {
  strings:
    $key_5d2f = { 09 47 [2] 7d 5f [2] 3a 5d [2] 7d 4c [2] 33 40 [2] 3f 4a [2] 28 41 [2] 33 0f [2] 0e }

  condition:
    any of them
}