rule TTP_XOR_MULT_DOSStub_dd3b {
  strings:
    $key_dd3b = { 89 53 [2] fd 4b [2] ba 49 [2] fd 58 [2] b3 54 [2] bf 5e [2] a8 55 [2] b3 1b [2] 8e }

  condition:
    any of them
}