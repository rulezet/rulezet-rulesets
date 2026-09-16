rule TTP_XOR_MULT_DOSStub_6ee1 {
  strings:
    $key_6ee1 = { 3a 89 [2] 4e 91 [2] 09 93 [2] 4e 82 [2] 00 8e [2] 0c 84 [2] 1b 8f [2] 00 c1 [2] 3d }

  condition:
    any of them
}