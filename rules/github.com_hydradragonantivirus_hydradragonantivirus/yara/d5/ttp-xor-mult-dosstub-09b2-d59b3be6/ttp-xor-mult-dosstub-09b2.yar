rule TTP_XOR_MULT_DOSStub_09b2 {
  strings:
    $key_09b2 = { 5d da [2] 29 c2 [2] 6e c0 [2] 29 d1 [2] 67 dd [2] 6b d7 [2] 7c dc [2] 67 92 [2] 5a }

  condition:
    any of them
}