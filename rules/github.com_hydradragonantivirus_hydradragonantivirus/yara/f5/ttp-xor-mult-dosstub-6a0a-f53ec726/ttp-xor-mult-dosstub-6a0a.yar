rule TTP_XOR_MULT_DOSStub_6a0a {
  strings:
    $key_6a0a = { 3e 62 [2] 4a 7a [2] 0d 78 [2] 4a 69 [2] 04 65 [2] 08 6f [2] 1f 64 [2] 04 2a [2] 39 }

  condition:
    any of them
}