rule TTP_XOR_QUAD_CurrentVersionRun_d48d {
  strings:
    $key_d48d = { 87 e2 [2] a3 ec [2] 88 c0 [2] a6 e2 [2] b2 f9 [2] bd e3 [2] a3 fe [2] a1 ff [2] ba f9 [2] a6 fe [2] ba d1 }

  condition:
    any of them
}