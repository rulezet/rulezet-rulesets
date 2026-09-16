rule TTP_XOR_MULT_DOSStub_d1fd {
  strings:
    $key_d1fd = { 85 95 [2] f1 8d [2] b6 8f [2] f1 9e [2] bf 92 [2] b3 98 [2] a4 93 [2] bf dd [2] 82 }

  condition:
    any of them
}