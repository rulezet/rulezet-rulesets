rule TTP_XOR_WriteProcessMemory_e939 {
  strings:
    $key_e939 = { be 4b [2] 8c 69 [2] 8a 5c [2] a4 5c [2] 9b 40 }

  condition:
    any of them
}