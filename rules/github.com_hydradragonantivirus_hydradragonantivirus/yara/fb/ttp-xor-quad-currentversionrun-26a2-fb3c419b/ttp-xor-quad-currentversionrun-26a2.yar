rule TTP_XOR_QUAD_CurrentVersionRun_26a2 {
  strings:
    $key_26a2 = { 75 cd [2] 51 c3 [2] 7a ef [2] 54 cd [2] 40 d6 [2] 4f cc [2] 51 d1 [2] 53 d0 [2] 48 d6 [2] 54 d1 [2] 48 fe }

  condition:
    any of them
}