rule TTP_XOR_WriteProcessMemory_2430 {
  strings:
    $key_2430 = { 73 42 [2] 41 60 [2] 47 55 [2] 69 55 [2] 56 49 }

  condition:
    any of them
}