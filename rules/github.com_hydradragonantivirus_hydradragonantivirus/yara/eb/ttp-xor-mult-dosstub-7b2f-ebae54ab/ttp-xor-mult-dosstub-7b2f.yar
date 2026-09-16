rule TTP_XOR_MULT_DOSStub_7b2f {
  strings:
    $key_7b2f = { 2f 47 [2] 5b 5f [2] 1c 5d [2] 5b 4c [2] 15 40 [2] 19 4a [2] 0e 41 [2] 15 0f [2] 28 }

  condition:
    any of them
}