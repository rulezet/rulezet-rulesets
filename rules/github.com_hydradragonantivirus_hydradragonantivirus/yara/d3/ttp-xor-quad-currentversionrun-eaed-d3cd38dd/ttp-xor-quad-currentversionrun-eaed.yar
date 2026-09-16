rule TTP_XOR_QUAD_CurrentVersionRun_eaed {
  strings:
    $key_eaed = { b9 82 [2] 9d 8c [2] b6 a0 [2] 98 82 [2] 8c 99 [2] 83 83 [2] 9d 9e [2] 9f 9f [2] 84 99 [2] 98 9e [2] 84 b1 }

  condition:
    any of them
}