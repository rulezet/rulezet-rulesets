rule TTP_XOR_QUAD_CurrentVersionRun_272d {
  strings:
    $key_272d = { 74 42 [2] 50 4c [2] 7b 60 [2] 55 42 [2] 41 59 [2] 4e 43 [2] 50 5e [2] 52 5f [2] 49 59 [2] 55 5e [2] 49 71 }

  condition:
    any of them
}