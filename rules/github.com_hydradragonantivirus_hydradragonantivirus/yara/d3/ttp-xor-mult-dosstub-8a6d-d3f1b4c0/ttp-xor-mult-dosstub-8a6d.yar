rule TTP_XOR_MULT_DOSStub_8a6d {
  strings:
    $key_8a6d = { de 05 [2] aa 1d [2] ed 1f [2] aa 0e [2] e4 02 [2] e8 08 [2] ff 03 [2] e4 4d [2] d9 }

  condition:
    any of them
}