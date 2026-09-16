rule TTP_XOR_QUAD_CurrentVersionRun_deb3 {
  strings:
    $key_deb3 = { 8d dc [2] a9 d2 [2] 82 fe [2] ac dc [2] b8 c7 [2] b7 dd [2] a9 c0 [2] ab c1 [2] b0 c7 [2] ac c0 [2] b0 ef }

  condition:
    any of them
}