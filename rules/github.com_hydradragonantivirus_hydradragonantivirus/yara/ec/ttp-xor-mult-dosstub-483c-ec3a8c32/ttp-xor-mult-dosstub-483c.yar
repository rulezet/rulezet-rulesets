rule TTP_XOR_MULT_DOSStub_483c {
  strings:
    $key_483c = { 1c 54 [2] 68 4c [2] 2f 4e [2] 68 5f [2] 26 53 [2] 2a 59 [2] 3d 52 [2] 26 1c [2] 1b }

  condition:
    any of them
}