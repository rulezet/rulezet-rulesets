rule TTP_XOR_MULT_DOSStub_dd0c {
  strings:
    $key_dd0c = { 89 64 [2] fd 7c [2] ba 7e [2] fd 6f [2] b3 63 [2] bf 69 [2] a8 62 [2] b3 2c [2] 8e }

  condition:
    any of them
}