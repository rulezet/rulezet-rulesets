rule TTP_XOR_QUAD_CurrentVersionRun_eb10 {
  strings:
    $key_eb10 = { b8 7f [2] 9c 71 [2] b7 5d [2] 99 7f [2] 8d 64 [2] 82 7e [2] 9c 63 [2] 9e 62 [2] 85 64 [2] 99 63 [2] 85 4c }

  condition:
    any of them
}