rule TTP_XOR_QUAD_CurrentVersionRun_6d83 {
  strings:
    $key_6d83 = { 3e ec [2] 1a e2 [2] 31 ce [2] 1f ec [2] 0b f7 [2] 04 ed [2] 1a f0 [2] 18 f1 [2] 03 f7 [2] 1f f0 [2] 03 df }

  condition:
    any of them
}