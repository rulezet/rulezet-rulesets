rule TTP_XOR_QUAD_CurrentVersionRun_eb3c {
  strings:
    $key_eb3c = { b8 53 [2] 9c 5d [2] b7 71 [2] 99 53 [2] 8d 48 [2] 82 52 [2] 9c 4f [2] 9e 4e [2] 85 48 [2] 99 4f [2] 85 60 }

  condition:
    any of them
}