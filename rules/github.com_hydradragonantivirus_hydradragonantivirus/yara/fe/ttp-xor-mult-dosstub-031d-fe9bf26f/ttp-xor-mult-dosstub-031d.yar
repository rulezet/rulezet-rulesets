rule TTP_XOR_MULT_DOSStub_031d {
  strings:
    $key_031d = { 57 75 [2] 23 6d [2] 64 6f [2] 23 7e [2] 6d 72 [2] 61 78 [2] 76 73 [2] 6d 3d [2] 50 }

  condition:
    any of them
}