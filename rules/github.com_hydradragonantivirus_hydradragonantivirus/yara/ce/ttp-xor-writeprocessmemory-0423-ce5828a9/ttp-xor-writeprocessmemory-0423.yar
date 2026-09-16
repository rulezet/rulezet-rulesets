rule TTP_XOR_WriteProcessMemory_0423 {
  strings:
    $key_0423 = { 53 51 [2] 61 73 [2] 67 46 [2] 49 46 [2] 76 5a }

  condition:
    any of them
}