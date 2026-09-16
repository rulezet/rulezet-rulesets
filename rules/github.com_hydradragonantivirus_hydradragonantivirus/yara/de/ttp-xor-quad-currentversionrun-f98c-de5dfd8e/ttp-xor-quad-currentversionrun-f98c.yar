rule TTP_XOR_QUAD_CurrentVersionRun_f98c {
  strings:
    $key_f98c = { aa e3 [2] 8e ed [2] a5 c1 [2] 8b e3 [2] 9f f8 [2] 90 e2 [2] 8e ff [2] 8c fe [2] 97 f8 [2] 8b ff [2] 97 d0 }

  condition:
    any of them
}