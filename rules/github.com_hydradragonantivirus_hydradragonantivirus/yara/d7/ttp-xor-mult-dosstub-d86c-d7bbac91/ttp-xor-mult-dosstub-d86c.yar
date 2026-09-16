rule TTP_XOR_MULT_DOSStub_d86c {
  strings:
    $key_d86c = { 8c 04 [2] f8 1c [2] bf 1e [2] f8 0f [2] b6 03 [2] ba 09 [2] ad 02 [2] b6 4c [2] 8b }

  condition:
    any of them
}