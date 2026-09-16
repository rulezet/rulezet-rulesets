rule TTP_XOR_MULT_DOSStub_3822 {
  strings:
    $key_3822 = { 6c 4a [2] 18 52 [2] 5f 50 [2] 18 41 [2] 56 4d [2] 5a 47 [2] 4d 4c [2] 56 02 [2] 6b }

  condition:
    any of them
}