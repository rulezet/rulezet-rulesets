rule TTP_XOR_QUAD_CurrentVersionRun_ed8c {
  strings:
    $key_ed8c = { be e3 [2] 9a ed [2] b1 c1 [2] 9f e3 [2] 8b f8 [2] 84 e2 [2] 9a ff [2] 98 fe [2] 83 f8 [2] 9f ff [2] 83 d0 }

  condition:
    any of them
}