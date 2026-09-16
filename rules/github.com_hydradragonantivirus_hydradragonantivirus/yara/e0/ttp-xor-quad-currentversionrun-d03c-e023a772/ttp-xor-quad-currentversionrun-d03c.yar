rule TTP_XOR_QUAD_CurrentVersionRun_d03c {
  strings:
    $key_d03c = { 83 53 [2] a7 5d [2] 8c 71 [2] a2 53 [2] b6 48 [2] b9 52 [2] a7 4f [2] a5 4e [2] be 48 [2] a2 4f [2] be 60 }

  condition:
    any of them
}