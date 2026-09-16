rule TTP_XOR_QUAD_CurrentVersionRun_29ee {
  strings:
    $key_29ee = { 7a 81 [2] 5e 8f [2] 75 a3 [2] 5b 81 [2] 4f 9a [2] 40 80 [2] 5e 9d [2] 5c 9c [2] 47 9a [2] 5b 9d [2] 47 b2 }

  condition:
    any of them
}