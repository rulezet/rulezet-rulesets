rule TTP_XOR_QUAD_CurrentVersionRun_8f8c {
  strings:
    $key_8f8c = { dc e3 [2] f8 ed [2] d3 c1 [2] fd e3 [2] e9 f8 [2] e6 e2 [2] f8 ff [2] fa fe [2] e1 f8 [2] fd ff [2] e1 d0 }

  condition:
    any of them
}