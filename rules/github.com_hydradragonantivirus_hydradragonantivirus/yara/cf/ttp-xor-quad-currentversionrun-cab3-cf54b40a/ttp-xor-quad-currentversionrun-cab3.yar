rule TTP_XOR_QUAD_CurrentVersionRun_cab3 {
  strings:
    $key_cab3 = { 99 dc [2] bd d2 [2] 96 fe [2] b8 dc [2] ac c7 [2] a3 dd [2] bd c0 [2] bf c1 [2] a4 c7 [2] b8 c0 [2] a4 ef }

  condition:
    any of them
}