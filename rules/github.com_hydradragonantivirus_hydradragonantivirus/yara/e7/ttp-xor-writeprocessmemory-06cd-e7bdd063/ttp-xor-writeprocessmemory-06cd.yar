rule TTP_XOR_WriteProcessMemory_06cd {
  strings:
    $key_06cd = { 51 bf [2] 63 9d [2] 65 a8 [2] 4b a8 [2] 74 b4 }

  condition:
    any of them
}