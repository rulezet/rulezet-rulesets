rule TTP_XOR_QUAD_CurrentVersionRun_158d {
  strings:
    $key_158d = { 46 e2 [2] 62 ec [2] 49 c0 [2] 67 e2 [2] 73 f9 [2] 7c e3 [2] 62 fe [2] 60 ff [2] 7b f9 [2] 67 fe [2] 7b d1 }

  condition:
    any of them
}