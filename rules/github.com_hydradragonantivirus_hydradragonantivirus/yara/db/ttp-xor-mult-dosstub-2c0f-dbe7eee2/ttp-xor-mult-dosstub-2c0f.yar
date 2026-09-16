rule TTP_XOR_MULT_DOSStub_2c0f {
  strings:
    $key_2c0f = { 78 67 [2] 0c 7f [2] 4b 7d [2] 0c 6c [2] 42 60 [2] 4e 6a [2] 59 61 [2] 42 2f [2] 7f }

  condition:
    any of them
}