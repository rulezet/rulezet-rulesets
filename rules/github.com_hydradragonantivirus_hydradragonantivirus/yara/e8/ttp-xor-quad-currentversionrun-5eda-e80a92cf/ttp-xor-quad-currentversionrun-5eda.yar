rule TTP_XOR_QUAD_CurrentVersionRun_5eda {
  strings:
    $key_5eda = { 0d b5 [2] 29 bb [2] 02 97 [2] 2c b5 [2] 38 ae [2] 37 b4 [2] 29 a9 [2] 2b a8 [2] 30 ae [2] 2c a9 [2] 30 86 }

  condition:
    any of them
}