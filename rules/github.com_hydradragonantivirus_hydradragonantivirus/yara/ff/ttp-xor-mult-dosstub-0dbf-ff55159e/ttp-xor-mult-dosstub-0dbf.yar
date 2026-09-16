rule TTP_XOR_MULT_DOSStub_0dbf {
  strings:
    $key_0dbf = { 59 d7 [2] 2d cf [2] 6a cd [2] 2d dc [2] 63 d0 [2] 6f da [2] 78 d1 [2] 63 9f [2] 5e }

  condition:
    any of them
}