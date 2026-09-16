rule TTP_XOR_QUAD_CurrentVersionRun_05b4 {
  strings:
    $key_05b4 = { 56 db [2] 72 d5 [2] 59 f9 [2] 77 db [2] 63 c0 [2] 6c da [2] 72 c7 [2] 70 c6 [2] 6b c0 [2] 77 c7 [2] 6b e8 }

  condition:
    any of them
}