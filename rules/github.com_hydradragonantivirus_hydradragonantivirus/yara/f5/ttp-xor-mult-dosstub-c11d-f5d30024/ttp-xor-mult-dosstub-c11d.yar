rule TTP_XOR_MULT_DOSStub_c11d {
  strings:
    $key_c11d = { 95 75 [2] e1 6d [2] a6 6f [2] e1 7e [2] af 72 [2] a3 78 [2] b4 73 [2] af 3d [2] 92 }

  condition:
    any of them
}