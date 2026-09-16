rule TTP_XOR_WriteProcessMemory_eabb {
  strings:
    $key_eabb = { bd c9 [2] 8f eb [2] 89 de [2] a7 de [2] 98 c2 }

  condition:
    any of them
}