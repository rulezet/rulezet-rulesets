rule TTP_XOR_QUAD_CurrentVersionRun_336a {
  strings:
    $key_336a = { 60 05 [2] 44 0b [2] 6f 27 [2] 41 05 [2] 55 1e [2] 5a 04 [2] 44 19 [2] 46 18 [2] 5d 1e [2] 41 19 [2] 5d 36 }

  condition:
    any of them
}