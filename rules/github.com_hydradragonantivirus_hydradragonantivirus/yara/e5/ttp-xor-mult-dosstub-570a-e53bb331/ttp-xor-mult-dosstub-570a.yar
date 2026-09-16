rule TTP_XOR_MULT_DOSStub_570a {
  strings:
    $key_570a = { 03 62 [2] 77 7a [2] 30 78 [2] 77 69 [2] 39 65 [2] 35 6f [2] 22 64 [2] 39 2a [2] 04 }

  condition:
    any of them
}