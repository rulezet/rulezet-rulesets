rule TTP_XOR_QUAD_CurrentVersionRun_164d {
  strings:
    $key_164d = { 45 22 [2] 61 2c [2] 4a 00 [2] 64 22 [2] 70 39 [2] 7f 23 [2] 61 3e [2] 63 3f [2] 78 39 [2] 64 3e [2] 78 11 }

  condition:
    any of them
}