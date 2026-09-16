rule TTP_XOR_QUAD_CurrentVersionRun_e332 {
  strings:
    $key_e332 = { b0 5d [2] 94 53 [2] bf 7f [2] 91 5d [2] 85 46 [2] 8a 5c [2] 94 41 [2] 96 40 [2] 8d 46 [2] 91 41 [2] 8d 6e }

  condition:
    any of them
}