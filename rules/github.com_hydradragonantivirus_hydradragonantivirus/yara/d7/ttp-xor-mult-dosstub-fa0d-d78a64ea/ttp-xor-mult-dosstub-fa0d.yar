rule TTP_XOR_MULT_DOSStub_fa0d {
  strings:
    $key_fa0d = { ae 65 [2] da 7d [2] 9d 7f [2] da 6e [2] 94 62 [2] 98 68 [2] 8f 63 [2] 94 2d [2] a9 }

  condition:
    any of them
}