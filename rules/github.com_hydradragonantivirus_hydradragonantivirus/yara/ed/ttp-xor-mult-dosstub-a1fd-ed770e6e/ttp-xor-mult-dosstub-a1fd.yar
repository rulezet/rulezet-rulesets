rule TTP_XOR_MULT_DOSStub_a1fd {
  strings:
    $key_a1fd = { f5 95 [2] 81 8d [2] c6 8f [2] 81 9e [2] cf 92 [2] c3 98 [2] d4 93 [2] cf dd [2] f2 }

  condition:
    any of them
}