rule TTP_XOR_MULT_DOSStub_c47f {
  strings:
    $key_c47f = { 90 17 [2] e4 0f [2] a3 0d [2] e4 1c [2] aa 10 [2] a6 1a [2] b1 11 [2] aa 5f [2] 97 }

  condition:
    any of them
}