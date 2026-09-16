rule TTP_XOR_MULT_DOSStub_dd6c {
  strings:
    $key_dd6c = { 89 04 [2] fd 1c [2] ba 1e [2] fd 0f [2] b3 03 [2] bf 09 [2] a8 02 [2] b3 4c [2] 8e }

  condition:
    any of them
}