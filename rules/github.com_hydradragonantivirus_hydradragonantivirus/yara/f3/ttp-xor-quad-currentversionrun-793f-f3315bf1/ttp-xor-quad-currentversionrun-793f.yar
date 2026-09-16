rule TTP_XOR_QUAD_CurrentVersionRun_793f {
  strings:
    $key_793f = { 2a 50 [2] 0e 5e [2] 25 72 [2] 0b 50 [2] 1f 4b [2] 10 51 [2] 0e 4c [2] 0c 4d [2] 17 4b [2] 0b 4c [2] 17 63 }

  condition:
    any of them
}