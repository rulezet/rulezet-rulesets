rule TTP_XOR_QUAD_CurrentVersionRun_b6fe {
  strings:
    $key_b6fe = { e5 91 [2] c1 9f [2] ea b3 [2] c4 91 [2] d0 8a [2] df 90 [2] c1 8d [2] c3 8c [2] d8 8a [2] c4 8d [2] d8 a2 }

  condition:
    any of them
}