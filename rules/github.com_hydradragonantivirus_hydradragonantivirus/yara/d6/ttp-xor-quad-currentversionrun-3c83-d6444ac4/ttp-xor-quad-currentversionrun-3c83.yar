rule TTP_XOR_QUAD_CurrentVersionRun_3c83 {
  strings:
    $key_3c83 = { 6f ec [2] 4b e2 [2] 60 ce [2] 4e ec [2] 5a f7 [2] 55 ed [2] 4b f0 [2] 49 f1 [2] 52 f7 [2] 4e f0 [2] 52 df }

  condition:
    any of them
}