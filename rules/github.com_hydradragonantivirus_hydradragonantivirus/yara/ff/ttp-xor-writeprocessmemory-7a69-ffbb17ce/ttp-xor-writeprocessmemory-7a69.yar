rule TTP_XOR_WriteProcessMemory_7a69 {
  strings:
    $key_7a69 = { 2d 1b [2] 1f 39 [2] 19 0c [2] 37 0c [2] 08 10 }

  condition:
    any of them
}