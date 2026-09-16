rule TTP_XOR_QUAD_CurrentVersionRun_502d {
  strings:
    $key_502d = { 03 42 [2] 27 4c [2] 0c 60 [2] 22 42 [2] 36 59 [2] 39 43 [2] 27 5e [2] 25 5f [2] 3e 59 [2] 22 5e [2] 3e 71 }

  condition:
    any of them
}