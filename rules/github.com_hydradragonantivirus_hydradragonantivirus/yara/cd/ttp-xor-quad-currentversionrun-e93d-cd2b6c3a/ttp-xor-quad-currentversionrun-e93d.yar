rule TTP_XOR_QUAD_CurrentVersionRun_e93d {
  strings:
    $key_e93d = { ba 52 [2] 9e 5c [2] b5 70 [2] 9b 52 [2] 8f 49 [2] 80 53 [2] 9e 4e [2] 9c 4f [2] 87 49 [2] 9b 4e [2] 87 61 }

  condition:
    any of them
}