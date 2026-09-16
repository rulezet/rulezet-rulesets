rule TTP_XOR_QUAD_CurrentVersionRun_de27 {
  strings:
    $key_de27 = { 8d 48 [2] a9 46 [2] 82 6a [2] ac 48 [2] b8 53 [2] b7 49 [2] a9 54 [2] ab 55 [2] b0 53 [2] ac 54 [2] b0 7b }

  condition:
    any of them
}