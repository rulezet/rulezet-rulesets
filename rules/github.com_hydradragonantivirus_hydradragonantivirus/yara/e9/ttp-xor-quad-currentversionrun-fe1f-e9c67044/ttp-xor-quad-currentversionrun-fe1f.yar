rule TTP_XOR_QUAD_CurrentVersionRun_fe1f {
  strings:
    $key_fe1f = { ad 70 [2] 89 7e [2] a2 52 [2] 8c 70 [2] 98 6b [2] 97 71 [2] 89 6c [2] 8b 6d [2] 90 6b [2] 8c 6c [2] 90 43 }

  condition:
    any of them
}