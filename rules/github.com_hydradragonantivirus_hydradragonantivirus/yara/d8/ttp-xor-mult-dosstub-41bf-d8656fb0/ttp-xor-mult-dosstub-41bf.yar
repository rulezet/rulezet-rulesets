rule TTP_XOR_MULT_DOSStub_41bf {
  strings:
    $key_41bf = { 15 d7 [2] 61 cf [2] 26 cd [2] 61 dc [2] 2f d0 [2] 23 da [2] 34 d1 [2] 2f 9f [2] 12 }

  condition:
    any of them
}