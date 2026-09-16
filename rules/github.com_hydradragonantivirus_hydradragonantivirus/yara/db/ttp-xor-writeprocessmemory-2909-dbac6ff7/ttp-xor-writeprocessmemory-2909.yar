rule TTP_XOR_WriteProcessMemory_2909 {
  strings:
    $key_2909 = { 7e 7b [2] 4c 59 [2] 4a 6c [2] 64 6c [2] 5b 70 }

  condition:
    any of them
}