rule TTP_XOR_MULT_DOSStub_527d {
  strings:
    $key_527d = { 06 15 [2] 72 0d [2] 35 0f [2] 72 1e [2] 3c 12 [2] 30 18 [2] 27 13 [2] 3c 5d [2] 01 }

  condition:
    any of them
}