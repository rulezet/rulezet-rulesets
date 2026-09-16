rule TTP_XOR_QUAD_CurrentVersionRun_358c {
  strings:
    $key_358c = { 66 e3 [2] 42 ed [2] 69 c1 [2] 47 e3 [2] 53 f8 [2] 5c e2 [2] 42 ff [2] 40 fe [2] 5b f8 [2] 47 ff [2] 5b d0 }

  condition:
    any of them
}