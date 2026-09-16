rule TTP_XOR_MULT_DOSStub_182d {
  strings:
    $key_182d = { 4c 45 [2] 38 5d [2] 7f 5f [2] 38 4e [2] 76 42 [2] 7a 48 [2] 6d 43 [2] 76 0d [2] 4b }

  condition:
    any of them
}