rule TTP_XOR_QUAD_CurrentVersionRun_ed90 {
  strings:
    $key_ed90 = { be ff [2] 9a f1 [2] b1 dd [2] 9f ff [2] 8b e4 [2] 84 fe [2] 9a e3 [2] 98 e2 [2] 83 e4 [2] 9f e3 [2] 83 cc }

  condition:
    any of them
}