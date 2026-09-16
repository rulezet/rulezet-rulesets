rule TTP_XOR_MULT_DOSStub_dae8 {
  strings:
    $key_dae8 = { 8e 80 [2] fa 98 [2] bd 9a [2] fa 8b [2] b4 87 [2] b8 8d [2] af 86 [2] b4 c8 [2] 89 }

  condition:
    any of them
}