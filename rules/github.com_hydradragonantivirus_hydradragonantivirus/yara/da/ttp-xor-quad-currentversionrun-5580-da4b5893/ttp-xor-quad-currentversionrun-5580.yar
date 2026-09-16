rule TTP_XOR_QUAD_CurrentVersionRun_5580 {
  strings:
    $key_5580 = { 06 ef [2] 22 e1 [2] 09 cd [2] 27 ef [2] 33 f4 [2] 3c ee [2] 22 f3 [2] 20 f2 [2] 3b f4 [2] 27 f3 [2] 3b dc }

  condition:
    any of them
}