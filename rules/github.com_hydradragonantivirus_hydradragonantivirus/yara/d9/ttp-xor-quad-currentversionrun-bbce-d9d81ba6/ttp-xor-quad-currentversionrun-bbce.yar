rule TTP_XOR_QUAD_CurrentVersionRun_bbce {
  strings:
    $key_bbce = { e8 a1 [2] cc af [2] e7 83 [2] c9 a1 [2] dd ba [2] d2 a0 [2] cc bd [2] ce bc [2] d5 ba [2] c9 bd [2] d5 92 }

  condition:
    any of them
}