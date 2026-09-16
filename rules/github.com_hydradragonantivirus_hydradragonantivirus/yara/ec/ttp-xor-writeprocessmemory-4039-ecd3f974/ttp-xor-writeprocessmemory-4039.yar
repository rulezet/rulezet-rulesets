rule TTP_XOR_WriteProcessMemory_4039 {
  strings:
    $key_4039 = { 17 4b [2] 25 69 [2] 23 5c [2] 0d 5c [2] 32 40 }

  condition:
    any of them
}