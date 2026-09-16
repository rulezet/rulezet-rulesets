rule TTP_XOR_QUAD_CurrentVersionRun_298c {
  strings:
    $key_298c = { 7a e3 [2] 5e ed [2] 75 c1 [2] 5b e3 [2] 4f f8 [2] 40 e2 [2] 5e ff [2] 5c fe [2] 47 f8 [2] 5b ff [2] 47 d0 }

  condition:
    any of them
}