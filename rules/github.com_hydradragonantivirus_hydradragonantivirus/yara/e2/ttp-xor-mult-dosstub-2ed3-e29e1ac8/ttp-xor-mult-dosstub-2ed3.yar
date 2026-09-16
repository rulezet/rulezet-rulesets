rule TTP_XOR_MULT_DOSStub_2ed3 {
  strings:
    $key_2ed3 = { 7a bb [2] 0e a3 [2] 49 a1 [2] 0e b0 [2] 40 bc [2] 4c b6 [2] 5b bd [2] 40 f3 [2] 7d }

  condition:
    any of them
}