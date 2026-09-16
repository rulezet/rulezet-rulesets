rule TTP_XOR_MULT_DOSStub_eabf {
  strings:
    $key_eabf = { be d7 [2] ca cf [2] 8d cd [2] ca dc [2] 84 d0 [2] 88 da [2] 9f d1 [2] 84 9f [2] b9 }

  condition:
    any of them
}