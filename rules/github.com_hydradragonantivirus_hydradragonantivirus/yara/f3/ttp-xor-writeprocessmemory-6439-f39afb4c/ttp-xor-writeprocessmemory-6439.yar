rule TTP_XOR_WriteProcessMemory_6439 {
  strings:
    $key_6439 = { 33 4b [2] 01 69 [2] 07 5c [2] 29 5c [2] 16 40 }

  condition:
    any of them
}