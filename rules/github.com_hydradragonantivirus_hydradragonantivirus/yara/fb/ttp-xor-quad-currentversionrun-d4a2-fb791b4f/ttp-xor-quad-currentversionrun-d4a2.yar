rule TTP_XOR_QUAD_CurrentVersionRun_d4a2 {
  strings:
    $key_d4a2 = { 87 cd [2] a3 c3 [2] 88 ef [2] a6 cd [2] b2 d6 [2] bd cc [2] a3 d1 [2] a1 d0 [2] ba d6 [2] a6 d1 [2] ba fe }

  condition:
    any of them
}