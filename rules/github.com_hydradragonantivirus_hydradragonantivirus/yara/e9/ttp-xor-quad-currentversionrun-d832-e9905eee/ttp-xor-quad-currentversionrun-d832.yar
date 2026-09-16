rule TTP_XOR_QUAD_CurrentVersionRun_d832 {
  strings:
    $key_d832 = { 8b 5d [2] af 53 [2] 84 7f [2] aa 5d [2] be 46 [2] b1 5c [2] af 41 [2] ad 40 [2] b6 46 [2] aa 41 [2] b6 6e }

  condition:
    any of them
}