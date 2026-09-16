rule TTP_XOR_MULT_DOSStub_072f {
  strings:
    $key_072f = { 53 47 [2] 27 5f [2] 60 5d [2] 27 4c [2] 69 40 [2] 65 4a [2] 72 41 [2] 69 0f [2] 54 }

  condition:
    any of them
}