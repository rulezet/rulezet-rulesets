rule TTP_XOR_QUAD_CurrentVersionRun_6bf2 {
  strings:
    $key_6bf2 = { 38 9d [2] 1c 93 [2] 37 bf [2] 19 9d [2] 0d 86 [2] 02 9c [2] 1c 81 [2] 1e 80 [2] 05 86 [2] 19 81 [2] 05 ae }

  condition:
    any of them
}