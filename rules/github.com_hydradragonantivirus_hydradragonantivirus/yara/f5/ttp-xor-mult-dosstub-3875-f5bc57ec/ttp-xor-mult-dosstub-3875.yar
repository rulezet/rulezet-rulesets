rule TTP_XOR_MULT_DOSStub_3875 {
  strings:
    $key_3875 = { 6c 1d [2] 18 05 [2] 5f 07 [2] 18 16 [2] 56 1a [2] 5a 10 [2] 4d 1b [2] 56 55 [2] 6b }

  condition:
    any of them
}