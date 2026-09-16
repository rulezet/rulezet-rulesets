rule TTP_XOR_QUAD_CurrentVersionRun_c4ee {
  strings:
    $key_c4ee = { 97 81 [2] b3 8f [2] 98 a3 [2] b6 81 [2] a2 9a [2] ad 80 [2] b3 9d [2] b1 9c [2] aa 9a [2] b6 9d [2] aa b2 }

  condition:
    any of them
}