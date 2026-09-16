rule TTP_XOR_QUAD_CurrentVersionRun_3833 {
  strings:
    $key_3833 = { 6b 5c [2] 4f 52 [2] 64 7e [2] 4a 5c [2] 5e 47 [2] 51 5d [2] 4f 40 [2] 4d 41 [2] 56 47 [2] 4a 40 [2] 56 6f }

  condition:
    any of them
}