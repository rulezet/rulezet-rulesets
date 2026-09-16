rule TTP_XOR_MULT_DOSStub_722d {
  strings:
    $key_722d = { 26 45 [2] 52 5d [2] 15 5f [2] 52 4e [2] 1c 42 [2] 10 48 [2] 07 43 [2] 1c 0d [2] 21 }

  condition:
    any of them
}