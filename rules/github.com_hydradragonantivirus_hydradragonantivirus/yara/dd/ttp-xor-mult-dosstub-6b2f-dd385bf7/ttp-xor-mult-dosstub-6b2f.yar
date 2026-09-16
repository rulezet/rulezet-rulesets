rule TTP_XOR_MULT_DOSStub_6b2f {
  strings:
    $key_6b2f = { 3f 47 [2] 4b 5f [2] 0c 5d [2] 4b 4c [2] 05 40 [2] 09 4a [2] 1e 41 [2] 05 0f [2] 38 }

  condition:
    any of them
}