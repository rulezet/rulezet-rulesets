rule TTP_XOR_QUAD_CurrentVersionRun_189f {
  strings:
    $key_189f = { 4b f0 [2] 6f fe [2] 44 d2 [2] 6a f0 [2] 7e eb [2] 71 f1 [2] 6f ec [2] 6d ed [2] 76 eb [2] 6a ec [2] 76 c3 }

  condition:
    any of them
}