rule TTP_XOR_WriteProcessMemory_23cd {
  strings:
    $key_23cd = { 74 bf [2] 46 9d [2] 40 a8 [2] 6e a8 [2] 51 b4 }

  condition:
    any of them
}