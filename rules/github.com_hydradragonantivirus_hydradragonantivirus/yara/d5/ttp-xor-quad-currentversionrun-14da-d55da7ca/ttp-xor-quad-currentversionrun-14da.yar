rule TTP_XOR_QUAD_CurrentVersionRun_14da {
  strings:
    $key_14da = { 47 b5 [2] 63 bb [2] 48 97 [2] 66 b5 [2] 72 ae [2] 7d b4 [2] 63 a9 [2] 61 a8 [2] 7a ae [2] 66 a9 [2] 7a 86 }

  condition:
    any of them
}