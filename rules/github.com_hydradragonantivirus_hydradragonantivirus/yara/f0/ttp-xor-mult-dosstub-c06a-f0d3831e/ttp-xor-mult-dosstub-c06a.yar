rule TTP_XOR_MULT_DOSStub_c06a {
  strings:
    $key_c06a = { 94 02 [2] e0 1a [2] a7 18 [2] e0 09 [2] ae 05 [2] a2 0f [2] b5 04 [2] ae 4a [2] 93 }

  condition:
    any of them
}