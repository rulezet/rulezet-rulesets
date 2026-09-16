rule TTP_XOR_QUAD_CurrentVersionRun_586d {
  strings:
    $key_586d = { 0b 02 [2] 2f 0c [2] 04 20 [2] 2a 02 [2] 3e 19 [2] 31 03 [2] 2f 1e [2] 2d 1f [2] 36 19 [2] 2a 1e [2] 36 31 }

  condition:
    any of them
}