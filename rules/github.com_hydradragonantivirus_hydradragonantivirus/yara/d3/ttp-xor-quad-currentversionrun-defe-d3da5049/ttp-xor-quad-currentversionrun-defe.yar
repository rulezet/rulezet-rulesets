rule TTP_XOR_QUAD_CurrentVersionRun_defe {
  strings:
    $key_defe = { 8d 91 [2] a9 9f [2] 82 b3 [2] ac 91 [2] b8 8a [2] b7 90 [2] a9 8d [2] ab 8c [2] b0 8a [2] ac 8d [2] b0 a2 }

  condition:
    any of them
}