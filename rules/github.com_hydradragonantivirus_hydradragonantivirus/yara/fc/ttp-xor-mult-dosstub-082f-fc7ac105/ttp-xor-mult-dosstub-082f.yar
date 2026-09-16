rule TTP_XOR_MULT_DOSStub_082f {
  strings:
    $key_082f = { 5c 47 [2] 28 5f [2] 6f 5d [2] 28 4c [2] 66 40 [2] 6a 4a [2] 7d 41 [2] 66 0f [2] 5b }

  condition:
    any of them
}