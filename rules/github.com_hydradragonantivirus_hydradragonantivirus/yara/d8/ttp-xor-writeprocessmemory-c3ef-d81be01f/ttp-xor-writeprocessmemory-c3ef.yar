rule TTP_XOR_WriteProcessMemory_c3ef {
  strings:
    $key_c3ef = { 94 9d [2] a6 bf [2] a0 8a [2] 8e 8a [2] b1 96 }

  condition:
    any of them
}