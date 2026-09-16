rule TTP_XOR_MULT_DOSStub_e52f {
  strings:
    $key_e52f = { b1 47 [2] c5 5f [2] 82 5d [2] c5 4c [2] 8b 40 [2] 87 4a [2] 90 41 [2] 8b 0f [2] b6 }

  condition:
    any of them
}