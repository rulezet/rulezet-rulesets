rule TTP_XOR_QUAD_CurrentVersionRun_eafc {
  strings:
    $key_eafc = { b9 93 [2] 9d 9d [2] b6 b1 [2] 98 93 [2] 8c 88 [2] 83 92 [2] 9d 8f [2] 9f 8e [2] 84 88 [2] 98 8f [2] 84 a0 }

  condition:
    any of them
}