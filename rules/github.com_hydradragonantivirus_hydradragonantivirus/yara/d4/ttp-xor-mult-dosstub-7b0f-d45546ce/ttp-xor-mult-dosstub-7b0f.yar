rule TTP_XOR_MULT_DOSStub_7b0f {
  strings:
    $key_7b0f = { 2f 67 [2] 5b 7f [2] 1c 7d [2] 5b 6c [2] 15 60 [2] 19 6a [2] 0e 61 [2] 15 2f [2] 28 }

  condition:
    any of them
}