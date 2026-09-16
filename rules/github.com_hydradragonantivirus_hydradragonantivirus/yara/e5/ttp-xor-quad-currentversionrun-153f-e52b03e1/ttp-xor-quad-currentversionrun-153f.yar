rule TTP_XOR_QUAD_CurrentVersionRun_153f {
  strings:
    $key_153f = { 46 50 [2] 62 5e [2] 49 72 [2] 67 50 [2] 73 4b [2] 7c 51 [2] 62 4c [2] 60 4d [2] 7b 4b [2] 67 4c [2] 7b 63 }

  condition:
    any of them
}