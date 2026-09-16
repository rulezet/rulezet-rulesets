rule TTP_XOR_MULT_DOSStub_adbd {
  strings:
    $key_adbd = { f9 d5 [2] 8d cd [2] ca cf [2] 8d de [2] c3 d2 [2] cf d8 [2] d8 d3 [2] c3 9d [2] fe }

  condition:
    any of them
}