rule TTP_XOR_QUAD_CurrentVersionRun_109f {
  strings:
    $key_109f = { 43 f0 [2] 67 fe [2] 4c d2 [2] 62 f0 [2] 76 eb [2] 79 f1 [2] 67 ec [2] 65 ed [2] 7e eb [2] 62 ec [2] 7e c3 }

  condition:
    any of them
}