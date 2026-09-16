rule TTP_XOR_WriteProcessMemory_ec69 {
  strings:
    $key_ec69 = { bb 1b [2] 89 39 [2] 8f 0c [2] a1 0c [2] 9e 10 }

  condition:
    any of them
}