rule TTP_XOR_WriteProcessMemory_fbab {
  strings:
    $key_fbab = { ac d9 [2] 9e fb [2] 98 ce [2] b6 ce [2] 89 d2 }

  condition:
    any of them
}