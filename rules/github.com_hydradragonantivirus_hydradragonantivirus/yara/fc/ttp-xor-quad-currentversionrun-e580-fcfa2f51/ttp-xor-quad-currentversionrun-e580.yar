rule TTP_XOR_QUAD_CurrentVersionRun_e580 {
  strings:
    $key_e580 = { b6 ef [2] 92 e1 [2] b9 cd [2] 97 ef [2] 83 f4 [2] 8c ee [2] 92 f3 [2] 90 f2 [2] 8b f4 [2] 97 f3 [2] 8b dc }

  condition:
    any of them
}