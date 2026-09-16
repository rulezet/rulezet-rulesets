rule TTP_XOR_QUAD_CurrentVersionRun_ed84 {
  strings:
    $key_ed84 = { be eb [2] 9a e5 [2] b1 c9 [2] 9f eb [2] 8b f0 [2] 84 ea [2] 9a f7 [2] 98 f6 [2] 83 f0 [2] 9f f7 [2] 83 d8 }

  condition:
    any of them
}