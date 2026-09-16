rule TTP_XOR_QUAD_CurrentVersionRun_f61f {
  strings:
    $key_f61f = { a5 70 [2] 81 7e [2] aa 52 [2] 84 70 [2] 90 6b [2] 9f 71 [2] 81 6c [2] 83 6d [2] 98 6b [2] 84 6c [2] 98 43 }

  condition:
    any of them
}