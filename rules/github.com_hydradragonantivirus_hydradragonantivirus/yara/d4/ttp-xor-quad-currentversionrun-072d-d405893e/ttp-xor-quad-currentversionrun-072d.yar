rule TTP_XOR_QUAD_CurrentVersionRun_072d {
  strings:
    $key_072d = { 54 42 [2] 70 4c [2] 5b 60 [2] 75 42 [2] 61 59 [2] 6e 43 [2] 70 5e [2] 72 5f [2] 69 59 [2] 75 5e [2] 69 71 }

  condition:
    any of them
}