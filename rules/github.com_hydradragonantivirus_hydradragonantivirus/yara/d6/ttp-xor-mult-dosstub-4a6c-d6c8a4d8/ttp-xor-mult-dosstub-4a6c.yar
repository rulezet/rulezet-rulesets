rule TTP_XOR_MULT_DOSStub_4a6c {
  strings:
    $key_4a6c = { 1e 04 [2] 6a 1c [2] 2d 1e [2] 6a 0f [2] 24 03 [2] 28 09 [2] 3f 02 [2] 24 4c [2] 19 }

  condition:
    any of them
}