rule TTP_XOR_QUAD_CurrentVersionRun_0d83 {
  strings:
    $key_0d83 = { 5e ec [2] 7a e2 [2] 51 ce [2] 7f ec [2] 6b f7 [2] 64 ed [2] 7a f0 [2] 78 f1 [2] 63 f7 [2] 7f f0 [2] 63 df }

  condition:
    any of them
}