rule TTP_XOR_QUAD_CurrentVersionRun_e68d {
  strings:
    $key_e68d = { b5 e2 [2] 91 ec [2] ba c0 [2] 94 e2 [2] 80 f9 [2] 8f e3 [2] 91 fe [2] 93 ff [2] 88 f9 [2] 94 fe [2] 88 d1 }

  condition:
    any of them
}