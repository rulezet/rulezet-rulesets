rule TTP_XOR_QUAD_CurrentVersionRun_2e1f {
  strings:
    $key_2e1f = { 7d 70 [2] 59 7e [2] 72 52 [2] 5c 70 [2] 48 6b [2] 47 71 [2] 59 6c [2] 5b 6d [2] 40 6b [2] 5c 6c [2] 40 43 }

  condition:
    any of them
}