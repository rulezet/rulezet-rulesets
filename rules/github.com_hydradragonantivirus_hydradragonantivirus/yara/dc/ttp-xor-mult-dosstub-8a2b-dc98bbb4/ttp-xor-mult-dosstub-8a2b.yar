rule TTP_XOR_MULT_DOSStub_8a2b {
  strings:
    $key_8a2b = { de 43 [2] aa 5b [2] ed 59 [2] aa 48 [2] e4 44 [2] e8 4e [2] ff 45 [2] e4 0b [2] d9 }

  condition:
    any of them
}