rule TTP_XOR_MULT_DOSStub_0b0f {
  strings:
    $key_0b0f = { 5f 67 [2] 2b 7f [2] 6c 7d [2] 2b 6c [2] 65 60 [2] 69 6a [2] 7e 61 [2] 65 2f [2] 58 }

  condition:
    any of them
}