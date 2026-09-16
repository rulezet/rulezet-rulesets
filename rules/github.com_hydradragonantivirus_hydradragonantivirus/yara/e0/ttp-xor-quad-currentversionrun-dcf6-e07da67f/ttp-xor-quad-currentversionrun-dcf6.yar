rule TTP_XOR_QUAD_CurrentVersionRun_dcf6 {
  strings:
    $key_dcf6 = { 8f 99 [2] ab 97 [2] 80 bb [2] ae 99 [2] ba 82 [2] b5 98 [2] ab 85 [2] a9 84 [2] b2 82 [2] ae 85 [2] b2 aa }

  condition:
    any of them
}