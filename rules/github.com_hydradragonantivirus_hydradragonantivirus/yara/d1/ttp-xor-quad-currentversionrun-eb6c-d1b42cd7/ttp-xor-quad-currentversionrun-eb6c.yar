rule TTP_XOR_QUAD_CurrentVersionRun_eb6c {
  strings:
    $key_eb6c = { b8 03 [2] 9c 0d [2] b7 21 [2] 99 03 [2] 8d 18 [2] 82 02 [2] 9c 1f [2] 9e 1e [2] 85 18 [2] 99 1f [2] 85 30 }

  condition:
    any of them
}