rule TTP_XOR_QUAD_CurrentVersionRun_17a2 {
  strings:
    $key_17a2 = { 44 cd [2] 60 c3 [2] 4b ef [2] 65 cd [2] 71 d6 [2] 7e cc [2] 60 d1 [2] 62 d0 [2] 79 d6 [2] 65 d1 [2] 79 fe }

  condition:
    any of them
}