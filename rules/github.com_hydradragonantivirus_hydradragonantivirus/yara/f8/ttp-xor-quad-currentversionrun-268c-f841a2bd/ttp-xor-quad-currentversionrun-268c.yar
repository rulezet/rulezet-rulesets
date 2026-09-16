rule TTP_XOR_QUAD_CurrentVersionRun_268c {
  strings:
    $key_268c = { 75 e3 [2] 51 ed [2] 7a c1 [2] 54 e3 [2] 40 f8 [2] 4f e2 [2] 51 ff [2] 53 fe [2] 48 f8 [2] 54 ff [2] 48 d0 }

  condition:
    any of them
}