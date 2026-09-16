rule TTP_XOR_QUAD_CurrentVersionRun_689f {
  strings:
    $key_689f = { 3b f0 [2] 1f fe [2] 34 d2 [2] 1a f0 [2] 0e eb [2] 01 f1 [2] 1f ec [2] 1d ed [2] 06 eb [2] 1a ec [2] 06 c3 }

  condition:
    any of them
}