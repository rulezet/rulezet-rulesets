rule TTP_XOR_QUAD_CurrentVersionRun_162d {
  strings:
    $key_162d = { 45 42 [2] 61 4c [2] 4a 60 [2] 64 42 [2] 70 59 [2] 7f 43 [2] 61 5e [2] 63 5f [2] 78 59 [2] 64 5e [2] 78 71 }

  condition:
    any of them
}