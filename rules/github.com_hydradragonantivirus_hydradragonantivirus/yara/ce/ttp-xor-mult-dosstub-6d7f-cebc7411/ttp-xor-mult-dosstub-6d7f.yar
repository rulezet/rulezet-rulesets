rule TTP_XOR_MULT_DOSStub_6d7f {
  strings:
    $key_6d7f = { 39 17 [2] 4d 0f [2] 0a 0d [2] 4d 1c [2] 03 10 [2] 0f 1a [2] 18 11 [2] 03 5f [2] 3e }

  condition:
    any of them
}