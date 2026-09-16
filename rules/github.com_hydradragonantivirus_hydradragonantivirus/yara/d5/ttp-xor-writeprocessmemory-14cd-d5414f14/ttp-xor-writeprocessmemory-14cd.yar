rule TTP_XOR_WriteProcessMemory_14cd {
  strings:
    $key_14cd = { 43 bf [2] 71 9d [2] 77 a8 [2] 59 a8 [2] 66 b4 }

  condition:
    any of them
}