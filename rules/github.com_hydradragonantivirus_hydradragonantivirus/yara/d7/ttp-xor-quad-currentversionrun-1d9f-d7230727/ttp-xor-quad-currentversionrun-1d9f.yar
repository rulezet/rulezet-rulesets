rule TTP_XOR_QUAD_CurrentVersionRun_1d9f {
  strings:
    $key_1d9f = { 4e f0 [2] 6a fe [2] 41 d2 [2] 6f f0 [2] 7b eb [2] 74 f1 [2] 6a ec [2] 68 ed [2] 73 eb [2] 6f ec [2] 73 c3 }

  condition:
    any of them
}