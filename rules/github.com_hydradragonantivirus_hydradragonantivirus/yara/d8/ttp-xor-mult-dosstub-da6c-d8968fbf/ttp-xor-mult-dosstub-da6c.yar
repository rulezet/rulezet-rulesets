rule TTP_XOR_MULT_DOSStub_da6c {
  strings:
    $key_da6c = { 8e 04 [2] fa 1c [2] bd 1e [2] fa 0f [2] b4 03 [2] b8 09 [2] af 02 [2] b4 4c [2] 89 }

  condition:
    any of them
}