rule TTP_XOR_QUAD_CurrentVersionRun_2183 {
  strings:
    $key_2183 = { 72 ec [2] 56 e2 [2] 7d ce [2] 53 ec [2] 47 f7 [2] 48 ed [2] 56 f0 [2] 54 f1 [2] 4f f7 [2] 53 f0 [2] 4f df }

  condition:
    any of them
}