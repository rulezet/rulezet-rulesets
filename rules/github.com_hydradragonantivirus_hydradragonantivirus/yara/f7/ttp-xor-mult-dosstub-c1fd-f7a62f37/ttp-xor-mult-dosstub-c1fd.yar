rule TTP_XOR_MULT_DOSStub_c1fd {
  strings:
    $key_c1fd = { 95 95 [2] e1 8d [2] a6 8f [2] e1 9e [2] af 92 [2] a3 98 [2] b4 93 [2] af dd [2] 92 }

  condition:
    any of them
}