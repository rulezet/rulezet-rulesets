rule TTP_XOR_MULT_DOSStub_117f {
  strings:
    $key_117f = { 45 17 [2] 31 0f [2] 76 0d [2] 31 1c [2] 7f 10 [2] 73 1a [2] 64 11 [2] 7f 5f [2] 42 }

  condition:
    any of them
}