rule TTP_XOR_MULT_DOSStub_097d {
  strings:
    $key_097d = { 5d 15 [2] 29 0d [2] 6e 0f [2] 29 1e [2] 67 12 [2] 6b 18 [2] 7c 13 [2] 67 5d [2] 5a }

  condition:
    any of them
}