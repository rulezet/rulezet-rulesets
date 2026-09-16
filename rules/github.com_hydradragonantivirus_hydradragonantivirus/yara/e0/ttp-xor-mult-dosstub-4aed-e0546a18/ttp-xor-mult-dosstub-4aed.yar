rule TTP_XOR_MULT_DOSStub_4aed {
  strings:
    $key_4aed = { 1e 85 [2] 6a 9d [2] 2d 9f [2] 6a 8e [2] 24 82 [2] 28 88 [2] 3f 83 [2] 24 cd [2] 19 }

  condition:
    any of them
}