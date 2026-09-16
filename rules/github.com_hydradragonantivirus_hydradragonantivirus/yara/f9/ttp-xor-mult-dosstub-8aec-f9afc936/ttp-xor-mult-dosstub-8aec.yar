rule TTP_XOR_MULT_DOSStub_8aec {
  strings:
    $key_8aec = { de 84 [2] aa 9c [2] ed 9e [2] aa 8f [2] e4 83 [2] e8 89 [2] ff 82 [2] e4 cc [2] d9 }

  condition:
    any of them
}