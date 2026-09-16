rule TTP_XOR_MULT_DOSStub_4822 {
  strings:
    $key_4822 = { 1c 4a [2] 68 52 [2] 2f 50 [2] 68 41 [2] 26 4d [2] 2a 47 [2] 3d 4c [2] 26 02 [2] 1b }

  condition:
    any of them
}