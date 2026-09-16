rule TTP_XOR_QUAD_CurrentVersionRun_242d {
  strings:
    $key_242d = { 77 42 [2] 53 4c [2] 78 60 [2] 56 42 [2] 42 59 [2] 4d 43 [2] 53 5e [2] 51 5f [2] 4a 59 [2] 56 5e [2] 4a 71 }

  condition:
    any of them
}