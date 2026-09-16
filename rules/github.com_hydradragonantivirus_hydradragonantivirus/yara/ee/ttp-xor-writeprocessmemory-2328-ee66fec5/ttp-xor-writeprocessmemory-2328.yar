rule TTP_XOR_WriteProcessMemory_2328 {
  strings:
    $key_2328 = { 74 5a [2] 46 78 [2] 40 4d [2] 6e 4d [2] 51 51 }

  condition:
    any of them
}