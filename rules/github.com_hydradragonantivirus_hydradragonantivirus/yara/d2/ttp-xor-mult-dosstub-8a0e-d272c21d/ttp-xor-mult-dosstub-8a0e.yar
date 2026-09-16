rule TTP_XOR_MULT_DOSStub_8a0e {
  strings:
    $key_8a0e = { de 66 [2] aa 7e [2] ed 7c [2] aa 6d [2] e4 61 [2] e8 6b [2] ff 60 [2] e4 2e [2] d9 }

  condition:
    any of them
}