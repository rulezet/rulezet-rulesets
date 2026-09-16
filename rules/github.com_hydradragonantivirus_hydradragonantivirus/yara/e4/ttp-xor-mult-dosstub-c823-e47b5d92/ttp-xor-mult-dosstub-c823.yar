rule TTP_XOR_MULT_DOSStub_c823 {
  strings:
    $key_c823 = { 9c 4b [2] e8 53 [2] af 51 [2] e8 40 [2] a6 4c [2] aa 46 [2] bd 4d [2] a6 03 [2] 9b }

  condition:
    any of them
}