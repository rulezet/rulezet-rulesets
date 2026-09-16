rule TTP_XOR_QUAD_CurrentVersionRun_3db3 {
  strings:
    $key_3db3 = { 6e dc [2] 4a d2 [2] 61 fe [2] 4f dc [2] 5b c7 [2] 54 dd [2] 4a c0 [2] 48 c1 [2] 53 c7 [2] 4f c0 [2] 53 ef }

  condition:
    any of them
}