rule TTP_XOR_QUAD_CurrentVersionRun_d8fc {
  strings:
    $key_d8fc = { 8b 93 [2] af 9d [2] 84 b1 [2] aa 93 [2] be 88 [2] b1 92 [2] af 8f [2] ad 8e [2] b6 88 [2] aa 8f [2] b6 a0 }

  condition:
    any of them
}