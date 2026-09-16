rule TTP_XOR_WriteProcessMemory_fbca {
  strings:
    $key_fbca = { ac b8 [2] 9e 9a [2] 98 af [2] b6 af [2] 89 b3 }

  condition:
    any of them
}