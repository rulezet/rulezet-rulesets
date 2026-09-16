rule TTP_XOR_MULT_DOSStub_3dbf {
  strings:
    $key_3dbf = { 69 d7 [2] 1d cf [2] 5a cd [2] 1d dc [2] 53 d0 [2] 5f da [2] 48 d1 [2] 53 9f [2] 6e }

  condition:
    any of them
}