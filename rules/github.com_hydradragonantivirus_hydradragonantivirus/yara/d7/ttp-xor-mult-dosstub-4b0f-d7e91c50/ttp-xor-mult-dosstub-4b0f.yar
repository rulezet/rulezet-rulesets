rule TTP_XOR_MULT_DOSStub_4b0f {
  strings:
    $key_4b0f = { 1f 67 [2] 6b 7f [2] 2c 7d [2] 6b 6c [2] 25 60 [2] 29 6a [2] 3e 61 [2] 25 2f [2] 18 }

  condition:
    any of them
}