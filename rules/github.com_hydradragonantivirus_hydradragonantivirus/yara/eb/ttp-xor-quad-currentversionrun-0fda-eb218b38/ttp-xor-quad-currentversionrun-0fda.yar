rule TTP_XOR_QUAD_CurrentVersionRun_0fda {
  strings:
    $key_0fda = { 5c b5 [2] 78 bb [2] 53 97 [2] 7d b5 [2] 69 ae [2] 66 b4 [2] 78 a9 [2] 7a a8 [2] 61 ae [2] 7d a9 [2] 61 86 }

  condition:
    any of them
}