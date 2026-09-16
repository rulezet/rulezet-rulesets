rule TTP_XOR_QUAD_CurrentVersionRun_b06d {
  strings:
    $key_b06d = { e3 02 [2] c7 0c [2] ec 20 [2] c2 02 [2] d6 19 [2] d9 03 [2] c7 1e [2] c5 1f [2] de 19 [2] c2 1e [2] de 31 }

  condition:
    any of them
}