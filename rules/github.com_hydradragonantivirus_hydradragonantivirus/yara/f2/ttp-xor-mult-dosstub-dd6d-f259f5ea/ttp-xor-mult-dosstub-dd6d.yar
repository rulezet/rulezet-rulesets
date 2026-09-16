rule TTP_XOR_MULT_DOSStub_dd6d {
  strings:
    $key_dd6d = { 89 05 [2] fd 1d [2] ba 1f [2] fd 0e [2] b3 02 [2] bf 08 [2] a8 03 [2] b3 4d [2] 8e }

  condition:
    any of them
}