rule TTP_XOR_MULT_DOSStub_1a2f {
  strings:
    $key_1a2f = { 4e 47 [2] 3a 5f [2] 7d 5d [2] 3a 4c [2] 74 40 [2] 78 4a [2] 6f 41 [2] 74 0f [2] 49 }

  condition:
    any of them
}