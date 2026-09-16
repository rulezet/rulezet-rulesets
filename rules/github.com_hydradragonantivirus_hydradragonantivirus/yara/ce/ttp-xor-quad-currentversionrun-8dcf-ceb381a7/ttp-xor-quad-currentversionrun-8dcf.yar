rule TTP_XOR_QUAD_CurrentVersionRun_8dcf {
  strings:
    $key_8dcf = { de a0 [2] fa ae [2] d1 82 [2] ff a0 [2] eb bb [2] e4 a1 [2] fa bc [2] f8 bd [2] e3 bb [2] ff bc [2] e3 93 }

  condition:
    any of them
}