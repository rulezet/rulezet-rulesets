rule TTP_XOR_WriteProcessMemory_2e01 {
  strings:
    $key_2e01 = { 79 73 [2] 4b 51 [2] 4d 64 [2] 63 64 [2] 5c 78 }

  condition:
    any of them
}