rule TTP_XOR_MULT_DOSStub_d88a {
  strings:
    $key_d88a = { 8c e2 [2] f8 fa [2] bf f8 [2] f8 e9 [2] b6 e5 [2] ba ef [2] ad e4 [2] b6 aa [2] 8b }

  condition:
    any of them
}