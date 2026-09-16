rule TTP_XOR_QUAD_CurrentVersionRun_a711 {
  strings:
    $key_a711 = { f4 7e [2] d0 70 [2] fb 5c [2] d5 7e [2] c1 65 [2] ce 7f [2] d0 62 [2] d2 63 [2] c9 65 [2] d5 62 [2] c9 4d }

  condition:
    any of them
}