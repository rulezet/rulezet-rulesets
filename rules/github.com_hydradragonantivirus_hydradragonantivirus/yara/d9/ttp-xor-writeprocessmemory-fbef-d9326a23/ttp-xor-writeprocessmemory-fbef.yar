rule TTP_XOR_WriteProcessMemory_fbef {
  strings:
    $key_fbef = { ac 9d [2] 9e bf [2] 98 8a [2] b6 8a [2] 89 96 }

  condition:
    any of them
}