rule TTP_XOR_MULT_DOSStub_daea {
  strings:
    $key_daea = { 8e 82 [2] fa 9a [2] bd 98 [2] fa 89 [2] b4 85 [2] b8 8f [2] af 84 [2] b4 ca [2] 89 }

  condition:
    any of them
}