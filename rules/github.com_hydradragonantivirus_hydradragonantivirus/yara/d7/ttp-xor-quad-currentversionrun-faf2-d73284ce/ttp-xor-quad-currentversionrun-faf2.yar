rule TTP_XOR_QUAD_CurrentVersionRun_faf2 {
  strings:
    $key_faf2 = { a9 9d [2] 8d 93 [2] a6 bf [2] 88 9d [2] 9c 86 [2] 93 9c [2] 8d 81 [2] 8f 80 [2] 94 86 [2] 88 81 [2] 94 ae }

  condition:
    any of them
}