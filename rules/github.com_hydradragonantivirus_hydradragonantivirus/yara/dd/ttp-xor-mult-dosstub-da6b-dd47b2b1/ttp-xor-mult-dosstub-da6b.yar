rule TTP_XOR_MULT_DOSStub_da6b {
  strings:
    $key_da6b = { 8e 03 [2] fa 1b [2] bd 19 [2] fa 08 [2] b4 04 [2] b8 0e [2] af 05 [2] b4 4b [2] 89 }

  condition:
    any of them
}