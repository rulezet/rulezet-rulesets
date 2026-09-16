rule TTP_XOR_QUAD_CurrentVersionRun_371f {
  strings:
    $key_371f = { 64 70 [2] 40 7e [2] 6b 52 [2] 45 70 [2] 51 6b [2] 5e 71 [2] 40 6c [2] 42 6d [2] 59 6b [2] 45 6c [2] 59 43 }

  condition:
    any of them
}