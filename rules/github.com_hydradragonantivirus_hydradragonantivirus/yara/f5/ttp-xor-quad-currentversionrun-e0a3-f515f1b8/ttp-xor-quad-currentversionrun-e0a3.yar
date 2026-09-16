rule TTP_XOR_QUAD_CurrentVersionRun_e0a3 {
  strings:
    $key_e0a3 = { b3 cc [2] 97 c2 [2] bc ee [2] 92 cc [2] 86 d7 [2] 89 cd [2] 97 d0 [2] 95 d1 [2] 8e d7 [2] 92 d0 [2] 8e ff }

  condition:
    any of them
}