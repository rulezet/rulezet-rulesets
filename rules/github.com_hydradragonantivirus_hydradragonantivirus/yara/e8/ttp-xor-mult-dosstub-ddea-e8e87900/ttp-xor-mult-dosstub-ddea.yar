rule TTP_XOR_MULT_DOSStub_ddea {
  strings:
    $key_ddea = { 89 82 [2] fd 9a [2] ba 98 [2] fd 89 [2] b3 85 [2] bf 8f [2] a8 84 [2] b3 ca [2] 8e }

  condition:
    any of them
}