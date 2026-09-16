rule TTP_XOR_QUAD_CurrentVersionRun_0626 {
  strings:
    $key_0626 = { 55 49 [2] 71 47 [2] 5a 6b [2] 74 49 [2] 60 52 [2] 6f 48 [2] 71 55 [2] 73 54 [2] 68 52 [2] 74 55 [2] 68 7a }

  condition:
    any of them
}