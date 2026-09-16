rule TTP_XOR_QUAD_CurrentVersionRun_c391 {
  strings:
    $key_c391 = { 90 fe [2] b4 f0 [2] 9f dc [2] b1 fe [2] a5 e5 [2] aa ff [2] b4 e2 [2] b6 e3 [2] ad e5 [2] b1 e2 [2] ad cd }

  condition:
    any of them
}