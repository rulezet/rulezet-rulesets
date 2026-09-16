rule TTP_XOR_MULT_DOSStub_717f {
  strings:
    $key_717f = { 25 17 [2] 51 0f [2] 16 0d [2] 51 1c [2] 1f 10 [2] 13 1a [2] 04 11 [2] 1f 5f [2] 22 }

  condition:
    any of them
}