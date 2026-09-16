rule TTP_XOR_WriteProcessMemory_13ee {
  strings:
    $key_13ee = { 44 9c [2] 76 be [2] 70 8b [2] 5e 8b [2] 61 97 }

  condition:
    any of them
}