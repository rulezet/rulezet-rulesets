rule TTP_XOR_MULT_DOSStub_1f3d {
  strings:
    $key_1f3d = { 4b 55 [2] 3f 4d [2] 78 4f [2] 3f 5e [2] 71 52 [2] 7d 58 [2] 6a 53 [2] 71 1d [2] 4c }

  condition:
    any of them
}