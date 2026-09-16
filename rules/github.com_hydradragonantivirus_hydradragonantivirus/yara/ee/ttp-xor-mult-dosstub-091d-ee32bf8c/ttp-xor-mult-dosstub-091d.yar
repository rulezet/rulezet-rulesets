rule TTP_XOR_MULT_DOSStub_091d {
  strings:
    $key_091d = { 5d 75 [2] 29 6d [2] 6e 6f [2] 29 7e [2] 67 72 [2] 6b 78 [2] 7c 73 [2] 67 3d [2] 5a }

  condition:
    any of them
}