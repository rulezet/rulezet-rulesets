rule TTP_XOR_QUAD_CurrentVersionRun_223f {
  strings:
    $key_223f = { 71 50 [2] 55 5e [2] 7e 72 [2] 50 50 [2] 44 4b [2] 4b 51 [2] 55 4c [2] 57 4d [2] 4c 4b [2] 50 4c [2] 4c 63 }

  condition:
    any of them
}