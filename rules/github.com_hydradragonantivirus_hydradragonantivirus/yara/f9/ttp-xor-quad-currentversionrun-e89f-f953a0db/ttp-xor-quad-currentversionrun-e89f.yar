rule TTP_XOR_QUAD_CurrentVersionRun_e89f {
  strings:
    $key_e89f = { bb f0 [2] 9f fe [2] b4 d2 [2] 9a f0 [2] 8e eb [2] 81 f1 [2] 9f ec [2] 9d ed [2] 86 eb [2] 9a ec [2] 86 c3 }

  condition:
    any of them
}