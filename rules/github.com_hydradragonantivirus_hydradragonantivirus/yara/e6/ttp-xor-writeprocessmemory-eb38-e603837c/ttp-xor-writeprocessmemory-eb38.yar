rule TTP_XOR_WriteProcessMemory_eb38 {
  strings:
    $key_eb38 = { bc 4a [2] 8e 68 [2] 88 5d [2] a6 5d [2] 99 41 }

  condition:
    any of them
}