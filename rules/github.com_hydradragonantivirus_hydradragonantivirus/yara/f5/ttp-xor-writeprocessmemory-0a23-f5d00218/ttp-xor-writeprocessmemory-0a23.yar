rule TTP_XOR_WriteProcessMemory_0a23 {
  strings:
    $key_0a23 = { 5d 51 [2] 6f 73 [2] 69 46 [2] 47 46 [2] 78 5a }

  condition:
    any of them
}