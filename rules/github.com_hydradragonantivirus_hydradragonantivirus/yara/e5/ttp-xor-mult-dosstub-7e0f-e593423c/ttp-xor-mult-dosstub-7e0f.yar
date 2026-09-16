rule TTP_XOR_MULT_DOSStub_7e0f {
  strings:
    $key_7e0f = { 2a 67 [2] 5e 7f [2] 19 7d [2] 5e 6c [2] 10 60 [2] 1c 6a [2] 0b 61 [2] 10 2f [2] 2d }

  condition:
    any of them
}