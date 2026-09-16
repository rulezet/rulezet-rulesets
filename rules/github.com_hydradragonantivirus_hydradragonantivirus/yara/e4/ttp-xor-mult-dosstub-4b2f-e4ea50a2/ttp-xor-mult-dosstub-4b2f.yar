rule TTP_XOR_MULT_DOSStub_4b2f {
  strings:
    $key_4b2f = { 1f 47 [2] 6b 5f [2] 2c 5d [2] 6b 4c [2] 25 40 [2] 29 4a [2] 3e 41 [2] 25 0f [2] 18 }

  condition:
    any of them
}