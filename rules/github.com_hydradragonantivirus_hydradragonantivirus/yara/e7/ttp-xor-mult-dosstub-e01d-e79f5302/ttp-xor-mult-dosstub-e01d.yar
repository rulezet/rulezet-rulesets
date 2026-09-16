rule TTP_XOR_MULT_DOSStub_e01d {
  strings:
    $key_e01d = { b4 75 [2] c0 6d [2] 87 6f [2] c0 7e [2] 8e 72 [2] 82 78 [2] 95 73 [2] 8e 3d [2] b3 }

  condition:
    any of them
}