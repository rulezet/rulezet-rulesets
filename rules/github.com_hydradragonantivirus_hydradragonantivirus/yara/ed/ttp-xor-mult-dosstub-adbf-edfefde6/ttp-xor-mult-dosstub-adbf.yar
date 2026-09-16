rule TTP_XOR_MULT_DOSStub_adbf {
  strings:
    $key_adbf = { f9 d7 [2] 8d cf [2] ca cd [2] 8d dc [2] c3 d0 [2] cf da [2] d8 d1 [2] c3 9f [2] fe }

  condition:
    any of them
}