rule TTP_XOR_WriteProcessMemory_7e01 {
  strings:
    $key_7e01 = { 29 73 [2] 1b 51 [2] 1d 64 [2] 33 64 [2] 0c 78 }

  condition:
    any of them
}