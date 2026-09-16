rule TTP_XOR_MULT_DOSStub_836a {
  strings:
    $key_836a = { d7 02 [2] a3 1a [2] e4 18 [2] a3 09 [2] ed 05 [2] e1 0f [2] f6 04 [2] ed 4a [2] d0 }

  condition:
    any of them
}