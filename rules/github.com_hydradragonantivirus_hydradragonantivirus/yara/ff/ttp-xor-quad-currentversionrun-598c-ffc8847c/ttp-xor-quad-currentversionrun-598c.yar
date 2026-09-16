rule TTP_XOR_QUAD_CurrentVersionRun_598c {
  strings:
    $key_598c = { 0a e3 [2] 2e ed [2] 05 c1 [2] 2b e3 [2] 3f f8 [2] 30 e2 [2] 2e ff [2] 2c fe [2] 37 f8 [2] 2b ff [2] 37 d0 }

  condition:
    any of them
}