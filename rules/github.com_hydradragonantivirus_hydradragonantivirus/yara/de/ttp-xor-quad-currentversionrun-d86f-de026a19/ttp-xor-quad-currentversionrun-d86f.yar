rule TTP_XOR_QUAD_CurrentVersionRun_d86f {
  strings:
    $key_d86f = { 8b 00 [2] af 0e [2] 84 22 [2] aa 00 [2] be 1b [2] b1 01 [2] af 1c [2] ad 1d [2] b6 1b [2] aa 1c [2] b6 33 }

  condition:
    any of them
}