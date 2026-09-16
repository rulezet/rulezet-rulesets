rule TTP_XOR_QUAD_CurrentVersionRun_040c {
  strings:
    $key_040c = { 57 63 [2] 73 6d [2] 58 41 [2] 76 63 [2] 62 78 [2] 6d 62 [2] 73 7f [2] 71 7e [2] 6a 78 [2] 76 7f [2] 6a 50 }

  condition:
    any of them
}