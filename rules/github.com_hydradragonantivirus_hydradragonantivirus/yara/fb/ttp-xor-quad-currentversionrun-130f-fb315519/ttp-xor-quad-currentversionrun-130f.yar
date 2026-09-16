rule TTP_XOR_QUAD_CurrentVersionRun_130f {
  strings:
    $key_130f = { 40 60 [2] 64 6e [2] 4f 42 [2] 61 60 [2] 75 7b [2] 7a 61 [2] 64 7c [2] 66 7d [2] 7d 7b [2] 61 7c [2] 7d 53 }

  condition:
    any of them
}