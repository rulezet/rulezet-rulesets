rule TTP_XOR_WriteProcessMemory_4859 {
  strings:
    $key_4859 = { 1f 2b [2] 2d 09 [2] 2b 3c [2] 05 3c [2] 3a 20 }

  condition:
    any of them
}