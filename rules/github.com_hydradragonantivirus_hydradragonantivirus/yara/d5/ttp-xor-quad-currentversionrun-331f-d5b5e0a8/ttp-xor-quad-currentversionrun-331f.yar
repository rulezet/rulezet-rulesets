rule TTP_XOR_QUAD_CurrentVersionRun_331f {
  strings:
    $key_331f = { 60 70 [2] 44 7e [2] 6f 52 [2] 41 70 [2] 55 6b [2] 5a 71 [2] 44 6c [2] 46 6d [2] 5d 6b [2] 41 6c [2] 5d 43 }

  condition:
    any of them
}