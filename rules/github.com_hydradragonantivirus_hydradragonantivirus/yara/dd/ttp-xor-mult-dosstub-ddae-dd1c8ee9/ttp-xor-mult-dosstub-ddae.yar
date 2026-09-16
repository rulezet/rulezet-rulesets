rule TTP_XOR_MULT_DOSStub_ddae {
  strings:
    $key_ddae = { 89 c6 [2] fd de [2] ba dc [2] fd cd [2] b3 c1 [2] bf cb [2] a8 c0 [2] b3 8e [2] 8e }

  condition:
    any of them
}