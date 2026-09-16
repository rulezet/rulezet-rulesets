rule TTP_XOR_MULT_DOSStub_6835 {
  strings:
    $key_6835 = { 3c 5d [2] 48 45 [2] 0f 47 [2] 48 56 [2] 06 5a [2] 0a 50 [2] 1d 5b [2] 06 15 [2] 3b }

  condition:
    any of them
}