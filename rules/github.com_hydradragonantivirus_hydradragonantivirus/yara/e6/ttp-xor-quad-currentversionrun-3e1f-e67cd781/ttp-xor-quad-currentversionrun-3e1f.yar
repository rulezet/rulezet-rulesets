rule TTP_XOR_QUAD_CurrentVersionRun_3e1f {
  strings:
    $key_3e1f = { 6d 70 [2] 49 7e [2] 62 52 [2] 4c 70 [2] 58 6b [2] 57 71 [2] 49 6c [2] 4b 6d [2] 50 6b [2] 4c 6c [2] 50 43 }

  condition:
    any of them
}