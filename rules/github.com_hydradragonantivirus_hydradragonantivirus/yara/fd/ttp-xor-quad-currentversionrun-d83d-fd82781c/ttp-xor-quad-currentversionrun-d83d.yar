rule TTP_XOR_QUAD_CurrentVersionRun_d83d {
  strings:
    $key_d83d = { 8b 52 [2] af 5c [2] 84 70 [2] aa 52 [2] be 49 [2] b1 53 [2] af 4e [2] ad 4f [2] b6 49 [2] aa 4e [2] b6 61 }

  condition:
    any of them
}