rule TTP_XOR_QUAD_CurrentVersionRun_789f {
  strings:
    $key_789f = { 2b f0 [2] 0f fe [2] 24 d2 [2] 0a f0 [2] 1e eb [2] 11 f1 [2] 0f ec [2] 0d ed [2] 16 eb [2] 0a ec [2] 16 c3 }

  condition:
    any of them
}