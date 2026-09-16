rule TTP_XOR_QUAD_CurrentVersionRun_1227 {
  strings:
    $key_1227 = { 41 48 [2] 65 46 [2] 4e 6a [2] 60 48 [2] 74 53 [2] 7b 49 [2] 65 54 [2] 67 55 [2] 7c 53 [2] 60 54 [2] 7c 7b }

  condition:
    any of them
}