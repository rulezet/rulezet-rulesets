rule TTP_XOR_QUAD_CurrentVersionRun_2fda {
  strings:
    $key_2fda = { 7c b5 [2] 58 bb [2] 73 97 [2] 5d b5 [2] 49 ae [2] 46 b4 [2] 58 a9 [2] 5a a8 [2] 41 ae [2] 5d a9 [2] 41 86 }

  condition:
    any of them
}