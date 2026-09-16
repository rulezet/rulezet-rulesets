rule TTP_XOR_QUAD_CurrentVersionRun_1e3f {
  strings:
    $key_1e3f = { 4d 50 [2] 69 5e [2] 42 72 [2] 6c 50 [2] 78 4b [2] 77 51 [2] 69 4c [2] 6b 4d [2] 70 4b [2] 6c 4c [2] 70 63 }

  condition:
    any of them
}