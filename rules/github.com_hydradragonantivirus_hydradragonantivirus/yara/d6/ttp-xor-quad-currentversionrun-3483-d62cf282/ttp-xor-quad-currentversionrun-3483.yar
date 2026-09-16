rule TTP_XOR_QUAD_CurrentVersionRun_3483 {
  strings:
    $key_3483 = { 67 ec [2] 43 e2 [2] 68 ce [2] 46 ec [2] 52 f7 [2] 5d ed [2] 43 f0 [2] 41 f1 [2] 5a f7 [2] 46 f0 [2] 5a df }

  condition:
    any of them
}