rule TTP_XOR_QUAD_CurrentVersionRun_301f {
  strings:
    $key_301f = { 63 70 [2] 47 7e [2] 6c 52 [2] 42 70 [2] 56 6b [2] 59 71 [2] 47 6c [2] 45 6d [2] 5e 6b [2] 42 6c [2] 5e 43 }

  condition:
    any of them
}