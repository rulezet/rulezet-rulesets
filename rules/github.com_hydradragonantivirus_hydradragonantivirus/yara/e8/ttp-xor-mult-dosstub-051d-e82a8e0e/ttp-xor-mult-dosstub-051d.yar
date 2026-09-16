rule TTP_XOR_MULT_DOSStub_051d {
  strings:
    $key_051d = { 51 75 [2] 25 6d [2] 62 6f [2] 25 7e [2] 6b 72 [2] 67 78 [2] 70 73 [2] 6b 3d [2] 56 }

  condition:
    any of them
}