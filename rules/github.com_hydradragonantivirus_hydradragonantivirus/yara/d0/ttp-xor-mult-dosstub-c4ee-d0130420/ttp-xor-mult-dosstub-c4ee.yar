rule TTP_XOR_MULT_DOSStub_c4ee {
  strings:
    $key_c4ee = { 90 86 [2] e4 9e [2] a3 9c [2] e4 8d [2] aa 81 [2] a6 8b [2] b1 80 [2] aa ce [2] 97 }

  condition:
    any of them
}