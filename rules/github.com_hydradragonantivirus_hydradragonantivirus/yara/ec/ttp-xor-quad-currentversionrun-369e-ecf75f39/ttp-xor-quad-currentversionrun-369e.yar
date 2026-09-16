rule TTP_XOR_QUAD_CurrentVersionRun_369e {
  strings:
    $key_369e = { 65 f1 [2] 41 ff [2] 6a d3 [2] 44 f1 [2] 50 ea [2] 5f f0 [2] 41 ed [2] 43 ec [2] 58 ea [2] 44 ed [2] 58 c2 }

  condition:
    any of them
}