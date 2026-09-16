rule TTP_XOR_QUAD_CurrentVersionRun_322d {
  strings:
    $key_322d = { 61 42 [2] 45 4c [2] 6e 60 [2] 40 42 [2] 54 59 [2] 5b 43 [2] 45 5e [2] 47 5f [2] 5c 59 [2] 40 5e [2] 5c 71 }

  condition:
    any of them
}