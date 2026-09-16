rule TTP_XOR_MULT_DOSStub_c067 {
  strings:
    $key_c067 = { 94 0f [2] e0 17 [2] a7 15 [2] e0 04 [2] ae 08 [2] a2 02 [2] b5 09 [2] ae 47 [2] 93 }

  condition:
    any of them
}