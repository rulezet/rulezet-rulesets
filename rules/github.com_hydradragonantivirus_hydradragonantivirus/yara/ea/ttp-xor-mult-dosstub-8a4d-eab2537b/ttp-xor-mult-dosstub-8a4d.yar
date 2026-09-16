rule TTP_XOR_MULT_DOSStub_8a4d {
  strings:
    $key_8a4d = { de 25 [2] aa 3d [2] ed 3f [2] aa 2e [2] e4 22 [2] e8 28 [2] ff 23 [2] e4 6d [2] d9 }

  condition:
    any of them
}