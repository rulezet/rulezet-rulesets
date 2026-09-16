rule TTP_XOR_MULT_DOSStub_481c {
  strings:
    $key_481c = { 1c 74 [2] 68 6c [2] 2f 6e [2] 68 7f [2] 26 73 [2] 2a 79 [2] 3d 72 [2] 26 3c [2] 1b }

  condition:
    any of them
}