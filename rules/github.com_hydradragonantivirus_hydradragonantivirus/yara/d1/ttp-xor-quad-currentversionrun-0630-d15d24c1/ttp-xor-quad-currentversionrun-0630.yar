rule TTP_XOR_QUAD_CurrentVersionRun_0630 {
  strings:
    $key_0630 = { 55 5f [2] 71 51 [2] 5a 7d [2] 74 5f [2] 60 44 [2] 6f 5e [2] 71 43 [2] 73 42 [2] 68 44 [2] 74 43 [2] 68 6c }

  condition:
    any of them
}