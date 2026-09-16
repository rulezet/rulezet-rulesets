rule TTP_XOR_MULT_DOSStub_dd6a {
  strings:
    $key_dd6a = { 89 02 [2] fd 1a [2] ba 18 [2] fd 09 [2] b3 05 [2] bf 0f [2] a8 04 [2] b3 4a [2] 8e }

  condition:
    any of them
}