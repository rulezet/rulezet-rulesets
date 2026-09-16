rule TTP_XOR_QUAD_CurrentVersionRun_330f {
  strings:
    $key_330f = { 60 60 [2] 44 6e [2] 6f 42 [2] 41 60 [2] 55 7b [2] 5a 61 [2] 44 7c [2] 46 7d [2] 5d 7b [2] 41 7c [2] 5d 53 }

  condition:
    any of them
}