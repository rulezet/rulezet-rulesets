rule TTP_XOR_MULT_DOSStub_7978 {
  strings:
    $key_7978 = { 2d 10 [2] 59 08 [2] 1e 0a [2] 59 1b [2] 17 17 [2] 1b 1d [2] 0c 16 [2] 17 58 [2] 2a }

  condition:
    any of them
}