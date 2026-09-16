rule TTP_XOR_MULT_DOSStub_c469 {
  strings:
    $key_c469 = { 90 01 [2] e4 19 [2] a3 1b [2] e4 0a [2] aa 06 [2] a6 0c [2] b1 07 [2] aa 49 [2] 97 }

  condition:
    any of them
}