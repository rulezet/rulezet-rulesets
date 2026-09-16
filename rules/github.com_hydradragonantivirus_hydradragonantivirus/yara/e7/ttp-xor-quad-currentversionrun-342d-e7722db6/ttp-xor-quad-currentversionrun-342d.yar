rule TTP_XOR_QUAD_CurrentVersionRun_342d {
  strings:
    $key_342d = { 67 42 [2] 43 4c [2] 68 60 [2] 46 42 [2] 52 59 [2] 5d 43 [2] 43 5e [2] 41 5f [2] 5a 59 [2] 46 5e [2] 5a 71 }

  condition:
    any of them
}