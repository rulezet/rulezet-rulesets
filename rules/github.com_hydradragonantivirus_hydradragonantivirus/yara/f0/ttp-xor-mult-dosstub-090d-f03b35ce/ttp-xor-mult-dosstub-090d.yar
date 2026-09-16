rule TTP_XOR_MULT_DOSStub_090d {
  strings:
    $key_090d = { 5d 65 [2] 29 7d [2] 6e 7f [2] 29 6e [2] 67 62 [2] 6b 68 [2] 7c 63 [2] 67 2d [2] 5a }

  condition:
    any of them
}