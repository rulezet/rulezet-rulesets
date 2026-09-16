rule TTP_XOR_QUAD_CurrentVersionRun_168c {
  strings:
    $key_168c = { 45 e3 [2] 61 ed [2] 4a c1 [2] 64 e3 [2] 70 f8 [2] 7f e2 [2] 61 ff [2] 63 fe [2] 78 f8 [2] 64 ff [2] 78 d0 }

  condition:
    any of them
}