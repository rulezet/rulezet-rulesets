rule TTP_XOR_QUAD_CurrentVersionRun_d63b {
  strings:
    $key_d63b = { 85 54 [2] a1 5a [2] 8a 76 [2] a4 54 [2] b0 4f [2] bf 55 [2] a1 48 [2] a3 49 [2] b8 4f [2] a4 48 [2] b8 67 }

  condition:
    any of them
}