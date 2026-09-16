rule TTP_XOR_QUAD_CurrentVersionRun_d82f {
  strings:
    $key_d82f = { 8b 40 [2] af 4e [2] 84 62 [2] aa 40 [2] be 5b [2] b1 41 [2] af 5c [2] ad 5d [2] b6 5b [2] aa 5c [2] b6 73 }

  condition:
    any of them
}