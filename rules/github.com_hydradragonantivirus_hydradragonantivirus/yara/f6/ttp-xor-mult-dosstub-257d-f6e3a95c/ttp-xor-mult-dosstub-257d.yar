rule TTP_XOR_MULT_DOSStub_257d {
  strings:
    $key_257d = { 71 15 [2] 05 0d [2] 42 0f [2] 05 1e [2] 4b 12 [2] 47 18 [2] 50 13 [2] 4b 5d [2] 76 }

  condition:
    any of them
}