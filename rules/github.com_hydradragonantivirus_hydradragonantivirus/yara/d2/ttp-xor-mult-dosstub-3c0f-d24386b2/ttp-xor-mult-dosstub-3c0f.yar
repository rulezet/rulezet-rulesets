rule TTP_XOR_MULT_DOSStub_3c0f {
  strings:
    $key_3c0f = { 68 67 [2] 1c 7f [2] 5b 7d [2] 1c 6c [2] 52 60 [2] 5e 6a [2] 49 61 [2] 52 2f [2] 6f }

  condition:
    any of them
}