rule TTP_XOR_WriteProcessMemory_2814 {
  strings:
    $key_2814 = { 7f 66 [2] 4d 44 [2] 4b 71 [2] 65 71 [2] 5a 6d }

  condition:
    any of them
}