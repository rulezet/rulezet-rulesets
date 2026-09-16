rule TTP_XOR_QUAD_CurrentVersionRun_cc3c {
  strings:
    $key_cc3c = { 9f 53 [2] bb 5d [2] 90 71 [2] be 53 [2] aa 48 [2] a5 52 [2] bb 4f [2] b9 4e [2] a2 48 [2] be 4f [2] a2 60 }

  condition:
    any of them
}