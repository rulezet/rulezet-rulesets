rule TTP_XOR_WriteProcessMemory_2bef {
  strings:
    $key_2bef = { 7c 9d [2] 4e bf [2] 48 8a [2] 66 8a [2] 59 96 }

  condition:
    any of them
}