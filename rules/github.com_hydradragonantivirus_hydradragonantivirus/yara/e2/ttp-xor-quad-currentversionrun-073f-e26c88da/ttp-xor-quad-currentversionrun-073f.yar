rule TTP_XOR_QUAD_CurrentVersionRun_073f {
  strings:
    $key_073f = { 54 50 [2] 70 5e [2] 5b 72 [2] 75 50 [2] 61 4b [2] 6e 51 [2] 70 4c [2] 72 4d [2] 69 4b [2] 75 4c [2] 69 63 }

  condition:
    any of them
}