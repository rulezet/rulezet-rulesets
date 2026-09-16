rule TTP_XOR_QUAD_CurrentVersionRun_e301 {
  strings:
    $key_e301 = { b0 6e [2] 94 60 [2] bf 4c [2] 91 6e [2] 85 75 [2] 8a 6f [2] 94 72 [2] 96 73 [2] 8d 75 [2] 91 72 [2] 8d 5d }

  condition:
    any of them
}