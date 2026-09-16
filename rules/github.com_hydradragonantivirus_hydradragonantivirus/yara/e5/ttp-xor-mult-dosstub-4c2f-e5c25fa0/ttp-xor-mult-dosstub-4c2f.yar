rule TTP_XOR_MULT_DOSStub_4c2f {
  strings:
    $key_4c2f = { 18 47 [2] 6c 5f [2] 2b 5d [2] 6c 4c [2] 22 40 [2] 2e 4a [2] 39 41 [2] 22 0f [2] 1f }

  condition:
    any of them
}