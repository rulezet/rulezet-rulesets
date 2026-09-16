rule TTP_XOR_MULT_DOSStub_036a {
  strings:
    $key_036a = { 57 02 [2] 23 1a [2] 64 18 [2] 23 09 [2] 6d 05 [2] 61 0f [2] 76 04 [2] 6d 4a [2] 50 }

  condition:
    any of them
}