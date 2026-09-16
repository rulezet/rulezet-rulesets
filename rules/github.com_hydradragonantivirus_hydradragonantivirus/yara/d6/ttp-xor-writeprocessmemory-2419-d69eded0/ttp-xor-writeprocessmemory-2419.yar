rule TTP_XOR_WriteProcessMemory_2419 {
  strings:
    $key_2419 = { 73 6b [2] 41 49 [2] 47 7c [2] 69 7c [2] 56 60 }

  condition:
    any of them
}